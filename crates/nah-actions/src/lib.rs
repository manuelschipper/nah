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

use paths::{host_integrity_class, path_scope, sensitivity};
use self_protection_tiers::classify as classify_protection;

mod bash;
use bash::features::{
    child_startup as bash_child_startup, content as bash_content, descendants as bash_descendants,
    descriptor_paths as bash_descriptor_paths, descriptor_state as bash_descriptor_state,
    descriptors as bash_descriptors, environment_disclosure as bash_environment_disclosure,
    executable_identity as bash_executable_identity, execution as bash_execution,
    filesystem as bash_filesystem, finalize as bash_finalize, flow as bash_flow, git as bash_git,
    git_config as bash_git_config, git_operations as bash_git_operations,
    invocation as bash_invocation, local_utilities as bash_local_utilities,
    logical_storage as bash_logical_storage, lookup as bash_lookup, model as bash_model,
    network as bash_network, project as bash_project, rsync_options as bash_rsync_options,
    self_protection as bash_self_protection, semantics as bash_semantics, socat as bash_socat,
    state as bash_state, symlinks as bash_symlinks, tar as bash_tar, targets as bash_targets,
    transforms as bash_transforms, wrappers as bash_wrappers,
};
mod codex_patch;
mod language_effects;
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
    VisibleCode(VisibleCode<'a>, &'a ToolCallInput),
}

#[derive(Clone, Copy)]
pub enum VisibleCode<'a> {
    Python { source: &'a str },
    OpenClawJavaScript { source: &'a str },
    OpenClawTypeScript { source: &'a str },
    Ipython { source: &'a str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Draft {
    Native(native::Draft),
    Bash(bash_model::Draft),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisPlan {
    draft: Draft,
    bash_coverage_draft: Option<bash_model::Draft>,
    observation_request: ObservationRequest,
    ambient_variables: Vec<(String, bash_model::VariableValue)>,
    inline_report: nah_inline::InlineReport,
    inline_failed: bool,
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

    pub fn inline_report(&self) -> &nah_inline::InlineReport {
        &self.inline_report
    }

    pub const fn inline_failed(&self) -> bool {
        self.inline_failed
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
    let (request_id, draft, bash_coverage_draft, inline_report, inline_failed) = match input {
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
            (
                "native-v1",
                Draft::Native(draft),
                None,
                nah_inline::InlineReport::default(),
                false,
            )
        }
        AnalysisInput::Bash(syntax, input) => {
            let (mut draft, mut coverage_draft, path_queries, inline_report, inline_failed) =
                bash::draft(
                    syntax,
                    call_site.requested_cwd(),
                    ctx.home(),
                    ctx.platform(),
                    ambient_variables,
                    self_protection.protected_paths(),
                );
            draft.complete &= input.normalization_complete();
            coverage_draft.complete &= input.normalization_complete();
            queries.extend(path_queries);
            (
                "bash-v1",
                Draft::Bash(draft),
                Some(coverage_draft),
                inline_report,
                inline_failed,
            )
        }
        AnalysisInput::VisibleCode(visible, input) => {
            let invocation_input = native::invocation_input(input);
            let (interpreter, interpreter_profile, source, persistent_ipython) = match visible {
                VisibleCode::Python { source } => ("python", "python", source, false),
                VisibleCode::OpenClawJavaScript { source } => {
                    ("javascript", "openclaw-javascript", source, false)
                }
                VisibleCode::OpenClawTypeScript { source } => {
                    ("typescript", "openclaw-typescript", source, false)
                }
                VisibleCode::Ipython { source } => ("ipython", "ipython", source, true),
            };
            let (mut draft, mut coverage_draft, path_queries, inline_report, inline_failed) =
                if persistent_ipython {
                    bash::visible_ipython_effect_draft(
                        input.tool(),
                        source,
                        invocation_input,
                        call_site.requested_cwd(),
                        ctx.home(),
                        ctx.platform(),
                        ambient_variables,
                        self_protection.protected_paths(),
                    )
                } else {
                    bash::visible_language_effect_draft(
                        input.tool(),
                        interpreter,
                        interpreter_profile,
                        source,
                        invocation_input,
                        call_site.requested_cwd(),
                        ctx.home(),
                        ctx.platform(),
                        ambient_variables,
                        self_protection.protected_paths(),
                    )
                };
            draft.complete &= input.normalization_complete();
            coverage_draft.complete &= input.normalization_complete();
            queries.extend(path_queries);
            (
                "language-v1",
                Draft::Bash(draft),
                Some(coverage_draft),
                inline_report,
                inline_failed,
            )
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
        bash_coverage_draft,
        observation_request,
        ambient_variables: requested_ambient_variables,
        inline_report,
        inline_failed,
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
    finalize_inner(plan, observation, false)
}

pub fn finalize_with_language_safety_stream(
    plan: AnalysisPlan,
    observation: Observation,
) -> (ActionStream, ActionStream) {
    let has_language_safety = matches!(
        &plan.draft,
        Draft::Bash(draft) if draft.stages.iter().any(|stage| stage.language_safety_only)
    );
    if !has_language_safety {
        let stream = finalize(plan, observation);
        return (stream.clone(), stream);
    }
    let language_safety_stream = finalize_inner(plan.clone(), observation.clone(), true);
    let action_stream = finalize(plan, observation);
    (action_stream, language_safety_stream)
}

fn finalize_inner(
    plan: AnalysisPlan,
    observation: Observation,
    include_language_safety: bool,
) -> ActionStream {
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
                } else if let Some(Err(error)) = observed_path(&observation, PATH_KEY) {
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
                    if error != ObservationFailure::Unavailable
                        && (!matches!(
                            error,
                            ObservationFailure::PermissionDenied | ObservationFailure::Timeout
                        ) || !block_relevant_lexical_filesystem(&filesystem))
                    {
                        return partial();
                    }
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
                } else if let Some(Err(error)) = observed_path(&observation, &patch_path_key(index))
                {
                    let Some(filesystem) = lexical_filesystem_effect(
                        draft.operation,
                        &draft.requested_path,
                        cwd,
                        roots,
                        &plan.trusted_roots,
                        &plan.home,
                        &plan.critical_paths,
                        plan.platform,
                        false,
                    ) else {
                        return partial();
                    };
                    if error != ObservationFailure::Unavailable
                        && (!matches!(
                            error,
                            ObservationFailure::PermissionDenied | ObservationFailure::Timeout
                        ) || !block_relevant_lexical_filesystem(&filesystem))
                    {
                        return partial();
                    }
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
        Draft::Native(native::Draft::Opaque {
            tool,
            input,
            complete,
        }) => {
            let coverage = if complete && input.complete() {
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
            let outer_complete = plan
                .bash_coverage_draft
                .and_then(|draft| {
                    bash_finalize::finalize(
                        draft,
                        &observation,
                        roots,
                        cwd,
                        &plan.home,
                        &plan.trusted_roots,
                        &plan.critical_paths,
                        plan.platform,
                        include_language_safety,
                    )
                })
                .is_some_and(|(complete, _, _)| complete);
            let Some((_complete, stages, flows)) = bash_finalize::finalize(
                draft,
                &observation,
                roots,
                cwd,
                &plan.home,
                &plan.trusted_roots,
                &plan.critical_paths,
                plan.platform,
                include_language_safety,
            ) else {
                return partial();
            };
            let coverage = if outer_complete {
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
    let host_integrity = [
        host_integrity_class(
            operation,
            requested_path,
            &target,
            home,
            platform,
            false,
            recursive,
        ),
        host_integrity_class(
            operation,
            path.resolved().as_str(),
            path.resolved(),
            home,
            platform,
            false,
            recursive,
        ),
    ]
    .into_iter()
    .flatten()
    .max();
    let selects_root = matches!(&scope, PathScope::Project { root } if root == &target);
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target,
            scope,
            sensitivity,
            protection,
            host_integrity,
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
    let host_integrity = host_integrity_class(
        operation,
        requested_path,
        &target,
        home,
        platform,
        false,
        recursive,
    );
    let selects_root = matches!(&scope, PathScope::Project { root } if root == &target);
    Some(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target,
            scope,
            sensitivity,
            protection,
            host_integrity,
            selects_root,
            selects_home: false,
            recursive,
            pattern: false,
        },
    })
}

fn block_relevant_lexical_filesystem(effect: &EffectKind) -> bool {
    matches!(
        effect,
        EffectKind::Filesystem { effect }
            if effect.sensitivity != nah_proto::action::Sensitivity::None
                || effect.host_integrity.is_some()
    )
}

fn partial() -> ActionStream {
    ActionStream::new(Coverage::Partial, vec![], vec![])
        .expect("nah-proto accepts an empty partial action stream")
}
