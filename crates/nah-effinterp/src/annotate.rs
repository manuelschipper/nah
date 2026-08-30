// UNDOCUMENTED-EFFINTERP: attaches nah identity labels to private effect plans.

use effinterp_proto::{AttrValue, Effect, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::action::{FilesystemOperation, PathScope};
use nah_proto::action_v2::{EffectAnnotation, PathLabel};
use nah_proto::ctx::Ctx;
use nah_proto::observation::{
    Observation, ObservationQuery, ObservationValue, Observed, PathKind, PathObservation, Root,
};

use crate::labels::host_integrity::host_integrity_class;
use crate::labels::runtime_cli;
use crate::labels::scope::path_scope;
use crate::labels::selects_home;
use crate::labels::sensitivity::sensitivity;
use crate::labels::tier;
use crate::observe::observation_path;

/// Produce one positional annotation for every effect in the plan.
pub fn annotate(plan: &Plan, observation: &Observation, ctx: &Ctx) -> Vec<EffectAnnotation> {
    let roots = observed_roots(observation);
    plan.effects
        .iter()
        .map(|effect| annotate_effect(plan, effect, observation, &roots, ctx))
        .collect()
}

fn annotate_effect(
    plan: &Plan,
    effect: &Effect,
    observation: &Observation,
    roots: &[Root],
    ctx: &Ctx,
) -> EffectAnnotation {
    if !effect.realm.is_host() {
        return EffectAnnotation::default();
    }
    match effect.operation.domain() {
        "filesystem" => EffectAnnotation {
            path: Some(annotate_path(effect, observation, roots, ctx)),
            runtime_cli: None,
        },
        "process" if effect.operation.as_str() == "process.exec" => EffectAnnotation {
            path: None,
            runtime_cli: annotate_process(plan, effect, ctx),
        },
        _ => EffectAnnotation::default(),
    }
}

fn annotate_path(
    effect: &Effect,
    observation: &Observation,
    roots: &[Root],
    ctx: &Ctx,
) -> PathLabel {
    let (requested, pattern) = match &effect.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => (path.as_str(), false),
        ResourceExpr::Pattern { family, pattern } if family.0 == "filesystem" => {
            (pattern.as_str(), true)
        }
        _ => return PathLabel::Unresolved,
    };
    let Some(query_path) = observation_path(&effect.resource) else {
        return PathLabel::Unresolved;
    };
    let Some(path) = observed_path(observation, query_path) else {
        return PathLabel::Unresolved;
    };
    let operation = filesystem_operation(effect.operation.as_str());
    let target = if operation == FilesystemOperation::Delete && path.kind() == PathKind::Symlink {
        path.resolved().clone()
    } else {
        path.realpath().unwrap_or_else(|| path.resolved()).clone()
    };
    let scope = path_scope(&target, roots, ctx.home(), ctx.platform());
    let trusted_roots = ctx
        .trust()
        .trusted_roots()
        .iter()
        .map(|root| root.path().clone())
        .collect::<Vec<_>>();
    let recursive = effect.attributes.get("recursive") == Some(&AttrValue::Bool(true));
    let sensitivity = sensitivity(requested, &target, ctx.home(), ctx.platform(), pattern);
    let protection = tier::classify(
        operation,
        &target,
        &target,
        roots,
        &trusted_roots,
        ctx.home(),
        &[],
        ctx.platform(),
        pattern,
    );
    let host_integrity = host_integrity_class(
        operation,
        requested,
        &target,
        ctx.home(),
        ctx.platform(),
        pattern,
        recursive,
    );
    let selects_root = matches!(&scope, PathScope::Project { root } if root == &target);
    let selects_home = selects_home(target.as_str(), ctx.home().as_str(), ctx.platform(), false)
        || selects_home(requested, ctx.home().as_str(), ctx.platform(), pattern);
    PathLabel::Resolved {
        path: target,
        scope,
        sensitivity,
        protection,
        host_integrity,
        selects_root,
        selects_home,
    }
}

fn annotate_process(plan: &Plan, effect: &Effect, ctx: &Ctx) -> Option<String> {
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::Process {
                executable,
                path,
                argv,
                ..
            },
    } = &effect.resource
    else {
        return None;
    };
    let argv = if argv.is_empty() {
        plan.execution_graph
            .nodes
            .get(effect.execution.0 as usize)
            .map(|node| node.argv.as_slice())
            .unwrap_or_default()
    } else {
        argv
    };
    let argv = literal_argv(argv)?;
    let recognized = runtime_cli::classify(executable, &argv, ctx.home(), ctx.platform());
    recognized
        .map(|runtime| runtime.as_str().to_owned())
        .or_else(|| {
            path.as_deref()
                .filter(|path| tier::process_is_critical(path, ctx.home(), ctx.platform()))
                .map(|_| "nah".to_owned())
        })
}

fn literal_argv(argv: &[ResourceExpr]) -> Option<Vec<String>> {
    argv.iter()
        .map(|argument| match argument {
            ResourceExpr::Literal { value } => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn filesystem_operation(operation: &str) -> FilesystemOperation {
    match operation.rsplit('.').next() {
        Some("read" | "metadata") => FilesystemOperation::Read,
        Some("delete" | "remove") => FilesystemOperation::Delete,
        _ => FilesystemOperation::Write,
    }
}

fn observed_roots(observation: &Observation) -> Vec<Root> {
    observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Roots {
                observed: Observed::Ok { value },
            } => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn observed_path<'a>(observation: &'a Observation, requested: &str) -> Option<&'a PathObservation> {
    observation.facts().iter().find_map(|fact| {
        let ObservationQuery::Path {
            requested: query, ..
        } = fact.query()
        else {
            return None;
        };
        if query != requested {
            return None;
        }
        match fact.value() {
            ObservationValue::Path {
                observed: Observed::Ok { value },
            } => Some(value),
            _ => None,
        }
    })
}
