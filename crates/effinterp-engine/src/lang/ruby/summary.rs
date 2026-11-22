use effinterp_proto::{CoverageLevel, Domain};
use lib_ruby_parser::Node;

use crate::module_summary::{CallEdge, FunctionEntry, ImportBinding, ModuleSummary};
use crate::summary::Summary;
use crate::{
    CallableValue, ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, ValueArgument,
};

use super::DOMAINS;
use super::file_context::{RubyFileContext, qualified_class_definitions};
use super::spawn_resources::materialize_ruby_spawn;
use super::summary_capture::capture_ruby_summary;

use super::module_load::{ruby_autoload_bindings, ruby_require_bindings};

/// Keep module execution separate from the parameterized summaries of callable bodies.
pub(super) fn summarize_ast(source: &str, root: &Node) -> ModuleSummary {
    let ctx = RubyFileContext::collect(source, root);
    let exported_definitions = qualified_class_definitions(root);

    let mut functions = Vec::new();
    for i in 0..ctx.defs.len() {
        let (key, params, body, class) = {
            let d = &ctx.defs[i];
            (
                d.key.clone(),
                d.params.clone(),
                d.body.clone(),
                d.class.clone(),
            )
        };
        let cap = capture_ruby_summary(body.as_deref(), &params, class.as_deref(), &ctx);
        let returns_instances = ctx
            .returns
            .get(&key)
            .cloned()
            .map(|c| vec![Some(c)])
            .unwrap_or_default();
        let visibility = if ctx.internal.contains(&key) {
            crate::CallableVisibility::Internal
        } else {
            crate::CallableVisibility::Public
        };
        functions.push(FunctionEntry {
            name: key,
            visibility,
            summary: Summary {
                control_flow: cap.control_flow,
                params,
                effects: {
                    let mut effects = cap.effects;
                    effects.extend(cap.spawns.iter().map(|(spawn, guard)| {
                        let mut effect = materialize_ruby_spawn(spawn);
                        effect.condition = guard.clone();
                        effect
                    }));
                    effects
                },
                effect_models: Vec::new(),
                transfers: cap.transfers,
                returns: None,
                boundaries: cap.boundaries,
                coverage: DOMAINS
                    .iter()
                    .map(|dm| (Domain::new(*dm), CoverageLevel::Full))
                    .collect(),
            },
            calls: cap.calls,
            returns_instances,
            ..Default::default()
        });
    }

    // Top-level (module-execution) calls, in an empty parameter scope. Class,
    // module and singleton-class bodies execute when defined and are
    // descended; method definition bodies are not.
    let module_capture = capture_ruby_summary(Some(root), &[], None, &ctx);
    let mut module_calls = module_capture.calls;
    let module_control_flow = module_capture.control_flow.calls_only();
    module_calls.extend(command_registration_edges(&ctx));

    let imports = ruby_require_bindings(root, true);
    let scoped_imports = ruby_autoload_bindings(root);
    let exports = imports
        .iter()
        .map(|binding| ImportBinding {
            local: "*".to_string(),
            module: binding.module.clone(),
            imported: None,
        })
        .collect();
    let mut summary = ModuleSummary {
        linkage: crate::Linkage {
            global_class_lookup: true,
            ..Default::default()
        },
        functions,
        module_calls,
        module_control_flow,
        module_effects: {
            let mut effects = module_capture.effects;
            effects.extend(module_capture.spawns.iter().map(|(spawn, guard)| {
                let mut effect = materialize_ruby_spawn(spawn);
                effect.condition = guard.clone();
                effect
            }));
            effects
        },
        module_transfers: module_capture.transfers,
        module_boundaries: module_capture.boundaries,
        imports,
        scoped_imports,
        load_path_roots: ctx.load_path.roots,
        exports,
        exported_definitions,
        classes: ctx.classes,
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |_| true);
    summary
}

/// Thor turns each public method in a command-table class into a callback at
/// class-definition time. Keep the class receiver on every registration so
/// repository composition can require the same class identity at dispatch.
fn command_registration_edges(ctx: &RubyFileContext) -> Vec<CallEdge> {
    let mut out = Vec::new();
    for class in &ctx.classes {
        let Some(methods) = ctx.commands.get(&class.name) else {
            continue;
        };
        for method in methods {
            let callback = format!("{}.{}", class.name, method);
            if out.iter().any(|edge: &CallEdge| {
                edge.arguments.first().is_some_and(|argument| {
                    matches!(
                        &argument.value.kind,
                        SemanticValueKind::Callable(CallableValue::Function { name })
                            if name == &callback
                    )
                })
            }) {
                continue;
            }
            out.push(CallEdge {
                callee: "desc".to_string(),
                arguments: vec![ValueArgument {
                    name: Some("command".to_string()),
                    index: 0,
                    value: SemanticValue::callable(callback),
                }],
                lifecycle_registration: true,
                receiver: Some(SemanticValue::object(ObjectIdentity::ModuleBinding {
                    scope: ScopeKey::Module { key: String::new() },
                    name: class.name.clone(),
                })),
                ..Default::default()
            });
        }
    }
    out
}
