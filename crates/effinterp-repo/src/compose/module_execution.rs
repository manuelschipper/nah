//! Module execution: which imported modules' top levels run, in what order,
//! and which local functions an entry module's execution roots reach.

use std::collections::{HashMap, HashSet};

use effinterp_engine::{CallEdge, ExternalCall, ImportBinding};
use effinterp_proto::{BoundaryReason, CalleeReference};

use super::accumulation::{push_composed_boundary, push_dependency};
use super::budget::{all_domains, owned_domains};
use super::function::enter_function;
use super::{
    BoundaryOccurrence, Composition, CompositionWalk, InstanceEnv, ReceiverContext, ResolvedCall,
    find_import, follow, push_module_effects,
};
use crate::linker::join_module;
use crate::module::{ModuleFile, ModuleRegistry};

/// Execute imported modules' top-level call edges (Python import semantics),
/// including `from pkg import name` when `pkg.name` is itself a submodule.
pub(super) fn execute_imports(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    path: &[String],
    stack: &mut Vec<(String, String)>,
    out: &mut Composition,
) {
    if registry.defers_python_registrations(&importer.path) {
        push_composed_boundary(
            out,
            BoundaryOccurrence {
                class: effinterp_proto::BoundaryClass::Unmodeled,
                reason: BoundaryReason::DYNAMIC_REGISTRATION,
                detail: format!(
                    "{} omits expansion of a large registration-only re-export set",
                    importer.path
                ),
                source_file: None,
                callee: None,
                domains: all_domains(),
                affected_resource: None,
                limit: None,
                path: path.to_vec(),
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
        return;
    }
    // Direct imports first (so playbook.py reaches constants.py before
    // descending into ansible.cli's import tree and hitting the budget).
    let mut next_files: Vec<&ModuleFile> = Vec::new();
    for binding in &importer.summary.imports {
        match registry.resolve_import(importer, binding) {
            Some(target) => {
                out.resolved_calls.push(ResolvedCall {
                    source_file: importer.path.clone(),
                    callee: CalleeReference {
                        module: binding.module.clone(),
                        symbol: "__module_init__".to_string(),
                    },
                });
                push_unseen(&mut next_files, &mut out.executed, target);
            }
            None => {
                let linker = registry.linker(importer.lang);
                let ruby_diagnostic = registry.ruby_import_diagnostic(importer, &binding.module);
                let classification = if ruby_diagnostic.is_some() {
                    None
                } else {
                    linker.classify_import(registry, importer, &binding.module)
                };
                // A repository boundary replaces the raw import boundary even
                // when the target remains unknown; it does not prove execution.
                if classification.is_some()
                    || ruby_diagnostic.is_some()
                    || linker.unknown_import_is_boundary()
                {
                    out.resolved_calls.push(ResolvedCall {
                        source_file: importer.path.clone(),
                        callee: CalleeReference {
                            module: binding.module.clone(),
                            symbol: "__module_init__".into(),
                        },
                    });
                }
                let (reason, detail, domains) = match classification {
                    Some(ExternalCall::Modeled | ExternalCall::Inert) => {
                        (None, String::new(), Vec::new())
                    }
                    // A recognized library clouds only the domains it can
                    // reach; an unrecognized import could be anything.
                    Some(ExternalCall::Unmodeled(domains)) => (
                        Some((
                            effinterp_proto::BoundaryClass::Unmodeled,
                            BoundaryReason::EXTERNAL_UNMODELED,
                        )),
                        linker.external_import_label(registry, importer, &binding.module),
                        owned_domains(domains),
                    ),
                    None if linker.unknown_import_is_boundary() => (
                        Some((
                            effinterp_proto::BoundaryClass::Unresolved,
                            BoundaryReason::CROSS_MODULE,
                        )),
                        ruby_diagnostic.unwrap_or_else(|| {
                            format!("import {:?} is not an analyzed repo file", binding.module)
                        }),
                        all_domains(),
                    ),
                    None => (None, String::new(), Vec::new()),
                };
                if let Some((class, reason)) = reason {
                    push_composed_boundary(
                        out,
                        BoundaryOccurrence {
                            class,
                            reason,
                            detail,
                            source_file: Some(importer.path.clone()),
                            callee: Some(CalleeReference {
                                module: binding.module.clone(),
                                symbol: "__module_init__".into(),
                            }),
                            domains,
                            affected_resource: None,
                            limit: None,
                            path: path.to_vec(),
                            via_dispatch: out.walk_via_dispatch.clone(),
                        },
                    );
                }
            }
        }
        if let Some(imported) = &binding.imported {
            let sub = ImportBinding {
                local: imported.clone(),
                module: join_module(&binding.module, imported),
                imported: None,
            };
            if let Some(target) = registry.resolve_import(importer, &sub) {
                push_unseen(&mut next_files, &mut out.executed, target);
            }
        }
    }
    for file in &next_files {
        run_module_toplevel(registry, file, path, stack, out);
    }
    for file in next_files {
        let mut next = path.to_vec();
        next.push(file.path.clone());
        execute_imports(registry, file, &next, stack, out);
    }
}

/// Run a module's top level (import-time calls and direct effects) once the
/// module has been marked executed. Used both for eager imports and for a
/// scoped import that first becomes live when a resolved call enters the file.
fn run_module_toplevel(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    path: &[String],
    stack: &mut Vec<(String, String)>,
    out: &mut Composition,
) {
    push_dependency(out, file.path.clone());
    let mut next = path.to_vec();
    next.push(file.path.clone());
    let no_callbacks = HashMap::new();
    let mut env = InstanceEnv::default();
    // Import-time execution is its own path, whatever call imported it.
    let required = std::mem::replace(&mut out.required, false);
    for edge in &file.summary.module_calls {
        // A top-level call to a function defined in the imported file
        // itself: unlike the entrypoint (whose plan inlines its own local
        // calls), no plan covers an imported file, so enter the function
        // here or its effects would be lost. An import binding of the same
        // name still wins, matching resolve_callee.
        if !edge.callee.contains('.')
            && edge.receiver.is_none()
            && find_import(&file.summary, &edge.callee).is_none()
            && file.function(&edge.callee).is_some()
        {
            CompositionWalk::run(registry, file, out, (&next, stack, &mut env), |walk| {
                enter_function(
                    walk,
                    file,
                    file,
                    &edge.callee,
                    edge,
                    ReceiverContext::default(),
                    false,
                )
            });
            continue;
        }
        CompositionWalk::run(registry, file, out, (&next, stack, &mut env), |walk| {
            follow(walk, file, edge, &no_callbacks)
        });
    }
    // The imported module's own top-level DIRECT effects (an
    // `os.environ.get(...)` at module scope, a class-body read) run at
    // import time; no plan covers an imported file, so surface them and
    // their unresolved boundaries here.
    push_module_effects(file, &next, out);
    out.required = required;
}

/// Import a module that a resolved call just entered: its top level runs once,
/// then its own imports, matching `import mod; mod.fn()` / a scoped
/// `from mod import fn; fn()`.
pub(super) fn ensure_module_executed(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    path: &[String],
    stack: &mut Vec<(String, String)>,
    out: &mut Composition,
) {
    if !out.executed.insert(file.path.clone()) {
        return;
    }
    run_module_toplevel(registry, file, path, stack, out);
    let mut next = path.to_vec();
    next.push(file.path.clone());
    execute_imports(registry, file, &next, stack, out);
}

fn push_unseen<'a>(
    out: &mut Vec<&'a ModuleFile>,
    seen: &mut HashSet<String>,
    file: &'a ModuleFile,
) {
    if seen.insert(file.path.clone()) {
        out.push(file);
    }
}

pub(super) fn push_unseen_file<'a>(out: &mut Vec<&'a ModuleFile>, file: &'a ModuleFile) {
    if !out.iter().any(|existing| existing.path == file.path) {
        out.push(file);
    }
}

/// The local functions reachable from the module's execution roots, by walking
/// the local call graph. Execution begins at the module's top-level calls
/// (`module_calls` plus its own main-guard calls; for compiled languages
/// `module_calls` are `main`'s direct calls);
/// each local call into another defined function extends the reachable set.
/// Cross-file edges of these functions are the ones the execution surface may
/// follow; a function no execution path reaches is excluded.
///
pub(super) fn execution_reachable(entry: &ModuleFile) -> HashSet<String> {
    let roots: Vec<&CallEdge> = entry
        .summary
        .module_calls
        .iter()
        .chain(&entry.summary.main_calls)
        .collect();
    let mut reachable = HashSet::new();
    let mut work: Vec<String> = roots
        .iter()
        .filter_map(|e| local_callee(entry, &e.callee))
        .collect();
    while let Some(name) = work.pop() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        if let Some(func) = entry.function(&name) {
            // Gated bodies and their descendants are walked at actual call sites
            // through enter_function_inner, after proving every decorator.
            if !func.decorator_gate.is_empty() {
                reachable.remove(&name);
                continue;
            }
            for edge in &func.calls {
                if let Some(local) = local_callee(entry, &edge.callee) {
                    work.push(local);
                }
            }
        }
    }
    reachable
}

/// The name of the local function a call edge targets, if it is a bare call to
/// a function defined in this module (not a `member` access, not an imported
/// binding). Matches how the frontends record intra-file call edges.
fn local_callee(entry: &ModuleFile, callee: &str) -> Option<String> {
    if callee.contains('.') {
        return None;
    }
    entry.function(callee).map(|_| callee.to_string())
}
