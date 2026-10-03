use std::collections::BTreeMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionEdgeKind, ExecutionRealm, PathPlatform, ProvenanceRef, ResourceExpr, Subject,
};

use crate::builder::PlanBuilder;
use crate::models::common::arg_node;
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::Transition;
use crate::value::unresolved_resource;

pub(super) fn ci_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(GithubActions)]
}

/// argv[0] of the synthetic command repository discovery emits for a GitHub
/// Actions workflow `run` step. The NUL prefix keeps it from naming a real executable.
pub const GITHUB_ACTIONS_DRIVER: &str = "\0effinterp:github-actions";
pub(crate) const GITHUB_ACTIONS_CONTAINER_DRIVER: &str = "\0effinterp:github-actions-container";

struct GithubActions;

impl CommandModel for GithubActions {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "ci/github-actions@v5"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &[GITHUB_ACTIONS_DRIVER, GITHUB_ACTIONS_CONTAINER_DRIVER]
    }

    fn records_process(&self) -> bool {
        false
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx.argv.first().and_then(|word| word.as_literal())
            == Some(GITHUB_ACTIONS_CONTAINER_DRIVER)
        {
            if let Some(origin) = ctx.argv.get(1).and_then(|word| word.as_literal())
                && let Some(source) = ctx.argv.get(2).and_then(|word| word.as_literal())
                && let Some(image) = ctx.argv.get(3).and_then(|word| word.as_literal())
            {
                let provenance = [
                    model_node,
                    arg_node(builder, ctx, 2),
                    arg_node(builder, ctx, 3),
                ];
                ctx.nest.nest(
                    builder,
                    Transition::file(Subject::Shell {
                        source: source.to_string(),
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .origin(origin.to_string())
                    .kind(ExecutionEdgeKind::ContainerRealm)
                    .realm(ExecutionRealm::Container {
                        runtime: "github-actions".to_string(),
                        name: image.to_string(),
                    })
                    .source_cwd(ctx.runtime_cwd)
                    .runtime_cwd(ctx.runtime_cwd)
                    .cwd(ctx.cwd_resource(), None),
                    &provenance,
                    ctx.depth,
                );
                return;
            }
            unresolved_ci_step(builder, model_node);
            return;
        }

        if ctx.argv.get(1).and_then(|word| word.as_literal()) == Some("run")
            && let Some(origin) = ctx.argv.get(2).and_then(|word| word.as_literal())
            && let Some(source) = ctx.argv.get(3).and_then(|word| word.as_literal())
            && let Some(shell) = ctx.argv.get(4).and_then(|word| word.as_literal())
            && github_shell_is_supported(shell)
            && let Some(working_directory) = ctx.argv.get(5).and_then(|word| word.as_literal())
            && let Some(container) = ctx.argv.get(6).and_then(|word| word.as_literal())
        {
            let mut provenance = vec![
                model_node,
                arg_node(builder, ctx, 3),
                arg_node(builder, ctx, 4),
            ];
            let (cwd, cwd_resource, source_cwd) = if working_directory.is_empty() {
                (
                    ctx.cwd.map(str::to_string),
                    ctx.cwd_resource(),
                    ctx.runtime_cwd.map(str::to_string),
                )
            } else if working_directory.contains("${{") {
                provenance.push(arg_node(builder, ctx, 5));
                (None, Some(unresolved_resource("filesystem")), None)
            } else {
                provenance.push(arg_node(builder, ctx, 5));
                (
                    Some(crate::paths::join_cwd(
                        ctx.cwd.unwrap_or_default(),
                        working_directory,
                    )),
                    Some(effinterp_proto::filesystem_path(
                        working_directory,
                        ctx.cwd_resource(),
                        PathPlatform::Posix,
                    )),
                    crate::paths::join_relative_file(ctx.runtime_cwd, working_directory),
                )
            };
            let mut environment = BTreeMap::new();
            let mut environment_nodes = BTreeMap::new();
            let tracks_host_context_environment = ctx.tracks_host_context_environment();
            for (index, assignment) in ctx.argv.iter().enumerate().skip(7) {
                let Some((name, value)) = assignment
                    .as_literal()
                    .and_then(|value| value.split_once('='))
                else {
                    continue;
                };
                let node = arg_node(builder, ctx, index as u32);
                if tracks_host_context_environment {
                    environment_nodes.insert(name.to_string(), node);
                } else {
                    provenance.push(node);
                }
                environment.insert(
                    name.to_string(),
                    Some(if value.contains("${{") {
                        unresolved_resource("value")
                    } else {
                        ResourceExpr::Literal {
                            value: value.to_string(),
                        }
                    }),
                );
            }
            let subject = if container.is_empty() {
                Subject::Shell {
                    source: source.to_string(),
                    cwd,
                    context: Default::default(),
                }
            } else {
                provenance.push(arg_node(builder, ctx, 6));
                Subject::Exec {
                    argv: vec![
                        GITHUB_ACTIONS_CONTAINER_DRIVER.to_string(),
                        origin.to_string(),
                        source.to_string(),
                        container.to_string(),
                    ],
                    cwd,
                    context: Default::default(),
                }
            };
            ctx.nest.nest(
                builder,
                Transition::file(subject)
                    .origin(origin.to_string())
                    .kind(ExecutionEdgeKind::CiRealm)
                    .realm(ExecutionRealm::Remote {
                        endpoint: "github-actions".to_string(),
                    })
                    .source_cwd(source_cwd.as_deref())
                    .runtime_cwd(source_cwd.as_deref())
                    .cwd(cwd_resource, None)
                    .environment(environment, environment_nodes, Default::default()),
                &provenance,
                ctx.depth,
            );
            return;
        }

        unresolved_ci_step(builder, model_node);
    }
}

fn unresolved_ci_step(builder: &mut PlanBuilder, model_node: ProvenanceRef) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRESOLVED_CI_STEP,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("process")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("GitHub Actions run step is not recoverable".to_string()),
    });
}

fn github_shell_is_supported(shell: &str) -> bool {
    let Some(command) = shell.split_whitespace().next() else {
        return false;
    };
    matches!(command.rsplit('/').next(), Some("bash" | "sh"))
}
