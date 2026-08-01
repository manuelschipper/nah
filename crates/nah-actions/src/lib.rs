#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Pure semantic lowering for typed native calls and parsed Bash.
//! `plan` interprets its input once into an AnalysisPlan containing a draft
//! and its ObservationRequest. `finalize` only fills exactly bound requested
//! facts to produce the ActionStream; it performs no I/O and never reparses.

use nah_proto::action::{ActionStream, Coverage, EffectKind, FilesystemEffect, PathScope};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFailure, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathObservation, Root, SymlinkTraversal,
};
use nah_proto::tool::{CallSite, ToolCallInput};

use paths::{path_scope, sensitivity};
use self_protection_tiers::classify as classify_protection;

mod bash;
mod bash_child_startup;
mod bash_content;
mod bash_descendants;
mod bash_descriptor_paths;
mod bash_descriptor_state;
mod bash_descriptors;
mod bash_executable_identity;
mod bash_execution;
mod bash_filesystem;
mod bash_finalize;
mod bash_flow;
mod bash_git;
mod bash_git_config;
mod bash_git_operations;
mod bash_invocation;
mod bash_local_utilities;
mod bash_logical_storage;
mod bash_lookup;
mod bash_model;
mod bash_network;
mod bash_project;
mod bash_rsync_options;
mod bash_self_protection;
mod bash_semantics;
mod bash_socat;
mod bash_state;
mod bash_symlinks;
mod bash_tar;
mod bash_targets;
mod bash_transforms;
mod bash_wrappers;
mod codex_patch;
mod native;
mod paths;
#[cfg(test)]
mod plan_tests;
mod self_protection_tiers;
mod shell_word;

const CWD_KEY: &str = "cwd";
const ROOTS_KEY: &str = "roots";
const PATH_KEY: &str = "target";
const GUARDS_KEY: &str = "project-guards";
pub(crate) const INVOCATION_EVIDENCE_CAP: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub enum AnalysisInput<'a> {
    Native(&'a ToolCallInput),
    Bash(&'a nah_parse::Syntax, &'a ToolCallInput),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Draft {
    Native(native::Draft),
    Bash(bash_model::Draft),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisPlan {
    draft: Draft,
    observation_request: ObservationRequest,
    ambient_variables: Vec<(String, bash_model::VariableValue)>,
    home: AbsolutePath,
    critical_paths: Vec<AbsolutePath>,
    trusted_roots: Vec<AbsolutePath>,
    platform: Platform,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelfProtectionProjection {
    protected_paths: Vec<AbsolutePath>,
}

impl SelfProtectionProjection {
    pub fn new(mut protected_paths: Vec<AbsolutePath>) -> Self {
        protected_paths.sort();
        protected_paths.dedup();
        Self { protected_paths }
    }

    fn protected_paths(&self) -> &[AbsolutePath] {
        &self.protected_paths
    }
}

impl AnalysisPlan {
    pub fn observation_request(&self) -> &ObservationRequest {
        &self.observation_request
    }
}

pub fn plan(input: AnalysisInput<'_>, ctx: &Ctx, call_site: &CallSite) -> AnalysisPlan {
    plan_with_self_protection(input, ctx, call_site, &SelfProtectionProjection::default())
}

pub fn plan_with_self_protection(
    input: AnalysisInput<'_>,
    ctx: &Ctx,
    call_site: &CallSite,
    self_protection: &SelfProtectionProjection,
) -> AnalysisPlan {
    plan_with_ambient_variables(input, ctx, call_site, &[], self_protection)
}

pub fn replan_with_environment_and_self_protection(
    input: AnalysisInput<'_>,
    ctx: &Ctx,
    call_site: &CallSite,
    observation: &Observation,
    self_protection: &SelfProtectionProjection,
) -> AnalysisPlan {
    let ambient_variables = ambient_variables(observation);
    plan_with_ambient_variables(input, ctx, call_site, &ambient_variables, self_protection)
}

fn plan_with_ambient_variables(
    input: AnalysisInput<'_>,
    ctx: &Ctx,
    call_site: &CallSite,
    ambient_variables: &[(String, bash_model::VariableValue)],
    self_protection: &SelfProtectionProjection,
) -> AnalysisPlan {
    let mut queries = vec![
        ObservationQuery::Cwd {
            key: CWD_KEY.into(),
            requested: call_site.requested_cwd().clone(),
        },
        ObservationQuery::Roots {
            key: ROOTS_KEY.into(),
            cwd_key: CWD_KEY.into(),
        },
        ObservationQuery::ProjectGuards {
            key: GUARDS_KEY.into(),
            roots_key: ROOTS_KEY.into(),
        },
    ];
    let (request_id, draft) = match input {
        AnalysisInput::Native(input) => {
            let draft = native::draft(input, call_site, ctx.platform());
            match &draft {
                native::Draft::Native { requested_path, .. } => {
                    queries.push(ObservationQuery::Path {
                        key: PATH_KEY.into(),
                        requested: requested_path.clone(),
                        cwd_key: CWD_KEY.into(),
                        inspect_descendants: false,
                        symlink_traversal: SymlinkTraversal::None,
                    });
                }
                native::Draft::Patch { effects, .. } => {
                    queries.extend(effects.iter().enumerate().map(|(index, effect)| {
                        ObservationQuery::Path {
                            key: patch_path_key(index),
                            requested: effect.requested_path.clone(),
                            cwd_key: CWD_KEY.into(),
                            inspect_descendants: false,
                            symlink_traversal: SymlinkTraversal::None,
                        }
                    }));
                }
                native::Draft::Opaque { .. } | native::Draft::Unsupported => {}
            }
            ("native-v1", Draft::Native(draft))
        }
        AnalysisInput::Bash(syntax, input) => {
            let (mut draft, path_queries) = bash::draft(
                syntax,
                call_site.requested_cwd(),
                ctx.home(),
                ctx.platform(),
                ambient_variables,
                self_protection.protected_paths(),
            );
            draft.complete &= input.normalization_complete();
            queries.extend(path_queries);
            ("bash-v1", Draft::Bash(draft))
        }
    };
    let observation_request = ObservationRequest::new(SchemaVersion::V1, request_id, queries)
        .expect("analysis observation query graph is valid");
    let requested_ambient_variables = ambient_variables
        .iter()
        .filter(|(name, _)| {
            observation_request.queries().iter().any(
                |query| matches!(query, ObservationQuery::Env { name: requested, .. } if requested == name),
            )
        })
        .cloned()
        .collect();
    AnalysisPlan {
        draft,
        observation_request,
        ambient_variables: requested_ambient_variables,
        home: ctx.home().clone(),
        critical_paths: self_protection.protected_paths().to_vec(),
        trusted_roots: ctx
            .trust()
            .trusted_roots()
            .iter()
            .map(|root| root.path().clone())
            .collect(),
        platform: ctx.platform(),
    }
}

pub fn finalize(plan: AnalysisPlan, observation: Observation) -> ActionStream {
    if observation.bind(&plan.observation_request).is_err() {
        return partial();
    }
    let ambient_variables_stable = ambient_variables_match(&plan.ambient_variables, &observation);
    let Some(roots) = observed_roots(&observation) else {
        return partial();
    };
    let Some(cwd) = observed_cwd(&observation) else {
        return partial();
    };

    let (coverage, stages, flows) = match plan.draft {
        Draft::Native(native::Draft::Native {
            tool,
            operation,
            filesystem_operation,
            requested_path,
            recursive,
            requires_file,
            complete,
            network,
            input,
        }) => {
            let Ok(invocation) = EffectKind::known_with_input(&tool, operation, input) else {
                return partial();
            };
            let invocation = invocation.with_invocation_cwd(cwd.clone());
            let (filesystem, observed_complete) =
                if let Some(Ok(path)) = observed_path(&observation, PATH_KEY) {
                    if requires_file && path.kind() != nah_proto::observation::PathKind::File {
                        return partial();
                    }
                    (
                        filesystem_effect(
                            filesystem_operation,
                            &requested_path,
                            path,
                            roots,
                            &plan.trusted_roots,
                            &plan.home,
                            &plan.critical_paths,
                            plan.platform,
                            recursive,
                        ),
                        true,
                    )
                } else if matches!(
                    observed_path(&observation, PATH_KEY),
                    Some(Err(ObservationFailure::Unavailable))
                ) {
                    let Some(filesystem) = lexical_filesystem_effect(
                        filesystem_operation,
                        &requested_path,
                        cwd,
                        roots,
                        &plan.trusted_roots,
                        &plan.home,
                        &plan.critical_paths,
                        plan.platform,
                        recursive,
                    ) else {
                        return partial();
                    };
                    (filesystem, false)
                } else {
                    return partial();
                };
            let mut effects = vec![invocation, filesystem];
            if network {
                effects.push(EffectKind::network(None));
            }
            let coverage = if complete && observed_complete {
                Coverage::Full
            } else {
                Coverage::Partial
            };
            (coverage, vec![effects], vec![])
        }
        Draft::Native(native::Draft::Patch {
            effects: drafts,
            input,
            complete: input_complete,
        }) => {
            let Ok(invocation) = EffectKind::known_with_input("apply_patch", "patch", input) else {
                return partial();
            };
            let invocation = invocation.with_invocation_cwd(cwd.clone());
            let mut effects = vec![invocation];
            let mut complete = input_complete;
            for (index, draft) in drafts.into_iter().enumerate() {
                if let Some(Ok(path)) = observed_path(&observation, &patch_path_key(index)) {
                    effects.push(filesystem_effect(
                        draft.operation,
                        &draft.requested_path,
                        path,
                        roots,
                        &plan.trusted_roots,
                        &plan.home,
                        &plan.critical_paths,
                        plan.platform,
                        false,
                    ));
                } else if matches!(
                    observed_path(&observation, &patch_path_key(index)),
                    Some(Err(ObservationFailure::Unavailable))
                ) && let Some(filesystem) = lexical_filesystem_effect(
                    draft.operation,
                    &draft.requested_path,
                    cwd,
                    roots,
                    &plan.trusted_roots,
                    &plan.home,
                    &plan.critical_paths,
                    plan.platform,
                    false,
                ) {
                    complete = false;
                    effects.push(filesystem);
                } else {
                    return partial();
                }
            }
            (
                if complete {
                    Coverage::Full
                } else {
                    Coverage::Partial
                },
                vec![effects],
                vec![],
            )
        }
        Draft::Native(native::Draft::Opaque { tool, input }) => {
            let coverage = if input.complete() {
                Coverage::Full
            } else {
                Coverage::Partial
            };
            let Ok(invocation) = EffectKind::opaque_with_input(&tool, input) else {
                return partial();
            };
            let invocation = invocation.with_invocation_cwd(cwd.clone());
            (coverage, vec![vec![invocation]], vec![])
        }
        Draft::Native(native::Draft::Unsupported) => return partial(),
        Draft::Bash(draft) => {
            let Some((complete, stages, flows)) = bash_finalize::finalize(
                draft,
                &observation,
                roots,
                cwd,
                &plan.home,
                &plan.trusted_roots,
                &plan.critical_paths,
                plan.platform,
            ) else {
                return partial();
            };
            let coverage = if complete {
                Coverage::Full
            } else {
                Coverage::Partial
            };
            (coverage, stages, flows)
        }
    };

    let coverage = if ambient_variables_stable {
        coverage
    } else {
        Coverage::Partial
    };
    ActionStream::new(coverage, stages, flows).unwrap_or_else(|_| partial())
}

fn ambient_variables(observation: &Observation) -> Vec<(String, bash_model::VariableValue)> {
    let mut variables = Vec::new();
    for fact in observation.facts() {
        let ObservationQuery::Env { name, .. } = fact.query() else {
            continue;
        };
        let ObservationValue::Env { observed } = fact.value() else {
            continue;
        };
        let value = match observed {
            Observed::Ok {
                value: EnvObservation::Value { text },
            } => bash_model::VariableValue::Static(text.clone()),
            Observed::Ok {
                value: EnvObservation::Unset,
            } => bash_model::VariableValue::Unset,
            Observed::Error { .. } => bash_model::VariableValue::Unknown,
        };
        if let Some((_, existing)) = variables.iter_mut().find(|(existing, _)| existing == name) {
            if existing != &value {
                *existing = bash_model::VariableValue::Unknown;
            }
        } else {
            variables.push((name.clone(), value));
        }
    }
    variables
}

fn ambient_variables_match(
    expected: &[(String, bash_model::VariableValue)],
    observation: &Observation,
) -> bool {
    expected.iter().all(|(name, expected)| {
        observation.facts().iter().any(|fact| {
            matches!(
                (fact.query(), fact.value(), expected),
                (
                    ObservationQuery::Env { name: observed_name, .. },
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Value { text },
                        },
                    },
                    bash_model::VariableValue::Static(expected),
                ) if observed_name == name && text == expected
            ) || matches!(
                (fact.query(), fact.value(), expected),
                (
                    ObservationQuery::Env { name: observed_name, .. },
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Unset,
                        },
                    },
                    bash_model::VariableValue::Unset,
                ) if observed_name == name
            ) || matches!(
                (fact.query(), fact.value(), expected),
                (
                    ObservationQuery::Env { name: observed_name, .. },
                    ObservationValue::Env {
                        observed: Observed::Error { .. },
                    },
                    bash_model::VariableValue::Unknown,
                ) if observed_name == name
            )
        })
    })
}

fn observed_cwd(observation: &Observation) -> Option<&AbsolutePath> {
    observation.facts().iter().find_map(|fact| {
        if fact.query().key() != CWD_KEY {
            return None;
        }
        match fact.value() {
            ObservationValue::Cwd {
                observed: Observed::Ok { value },
            } => Some(value),
            _ => None,
        }
    })
}

fn observed_roots(observation: &Observation) -> Option<&[Root]> {
    observation.facts().iter().find_map(|fact| {
        if fact.query().key() != ROOTS_KEY {
            return None;
        }
        match fact.value() {
            ObservationValue::Roots {
                observed: Observed::Ok { value },
            } => Some(value.as_slice()),
            _ => None,
        }
    })
}

fn observed_path<'a>(
    observation: &'a Observation,
    key: &str,
) -> Option<Result<&'a PathObservation, ObservationFailure>> {
    observation.facts().iter().find_map(|fact| {
        if fact.query().key() != key {
            return None;
        }
        match fact.value() {
            ObservationValue::Path {
                observed: Observed::Ok { value },
            } => Some(Ok(value)),
            ObservationValue::Path {
                observed: Observed::Error { error },
            } => Some(Err(*error)),
            _ => None,
        }
    })
}

fn patch_path_key(index: usize) -> String {
    format!("patch-target-{index:04}")
}

#[allow(clippy::too_many_arguments)]
fn filesystem_effect(
    operation: nah_proto::action::FilesystemOperation,
    requested_path: &str,
    path: &PathObservation,
    roots: &[Root],
    trusted_roots: &[AbsolutePath],
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    recursive: bool,
) -> EffectKind {
    let target = if operation == nah_proto::action::FilesystemOperation::Delete
        && path.kind() == nah_proto::observation::PathKind::Symlink
    {
        path.resolved().clone()
    } else {
        path.realpath().unwrap_or_else(|| path.resolved()).clone()
    };
    let scope = path_scope(&target, roots, home, platform);
    let sensitivity = sensitivity(requested_path, &target, home, platform, false);
    let protection = classify_protection(
        operation,
        &target,
        &target,
        roots,
        trusted_roots,
        home,
        critical_paths,
        platform,
        false,
    );
    let selects_root = matches!(&scope, PathScope::Project { root } if root == &target);
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target,
            scope,
            sensitivity,
            protection,
            selects_root,
            selects_home: false,
            recursive,
            pattern: false,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn lexical_filesystem_effect(
    operation: nah_proto::action::FilesystemOperation,
    requested_path: &str,
    cwd: &AbsolutePath,
    roots: &[Root],
    trusted_roots: &[AbsolutePath],
    home: &AbsolutePath,
    critical_paths: &[AbsolutePath],
    platform: Platform,
    recursive: bool,
) -> Option<EffectKind> {
    let target = if AbsolutePath::new(platform, requested_path).is_ok() {
        AbsolutePath::new(platform, requested_path).ok()?
    } else {
        AbsolutePath::new(
            platform,
            paths::join(cwd.as_str(), requested_path, platform),
        )
        .ok()?
    };
    let scope = path_scope(&target, roots, home, platform);
    let sensitivity = sensitivity(requested_path, &target, home, platform, false);
    let protection = classify_protection(
        operation,
        &target,
        &target,
        roots,
        trusted_roots,
        home,
        critical_paths,
        platform,
        false,
    );
    let selects_root = matches!(&scope, PathScope::Project { root } if root == &target);
    Some(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target,
            scope,
            sensitivity,
            protection,
            selects_root,
            selects_home: false,
            recursive,
            pattern: false,
        },
    })
}

fn partial() -> ActionStream {
    ActionStream::new(Coverage::Partial, vec![], vec![])
        .expect("nah-proto accepts an empty partial action stream")
}
