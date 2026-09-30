//! Framework entry scripts that hand their arguments to the framework's
//! command dispatcher: Django's `manage.py`, Laravel's `artisan` and
//! Symfony's `bin/console`. Nah names the dispatcher from the script's
//! conventional file name, so the script's own identity stays a boundary.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::arg_node;
use crate::word::Word;

/// The command model whose dispatcher a `language` entry script named by
/// `path` runs, from its file name alone.
pub(crate) fn dispatcher(language: &str, path: &str) -> Option<&'static str> {
    match (language, path.rsplit('/').next()?) {
        ("python", "manage.py") => Some("django-admin"),
        ("php", "artisan") => Some("artisan"),
        ("php", "console") => Some("console"),
        _ => None,
    }
}

/// Runs the words from `args_start` on through `command`'s model, as the
/// entry script at `script_index` hands them to its framework's dispatcher.
pub(crate) fn dispatch_entry_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    script_index: usize,
    args_start: usize,
    command: &'static str,
) {
    let script = arg_node(builder, ctx, script_index as u32);
    builder.boundary(Boundary {
        reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("database"), Domain::new("process")],
        provenance: vec![model_node, script],
        limit: None,
        detail: Some(format!(
            "the entry script is read as the framework's {command} dispatcher by its file name; the file itself is project code"
        )),
    });
    let mut argv = vec![Word::literal(command)];
    argv.extend_from_slice(&ctx.argv[args_start..]);
    let argv_provenance = std::iter::once(vec![model_node, script])
        .chain((args_start..ctx.argv.len()).map(|index| ctx.argv_provenance_at(builder, index)))
        .collect::<Vec<_>>();
    ctx.delegate_command_model(
        builder,
        &argv,
        Some(&argv_provenance),
        &[model_node, script],
    );
}
