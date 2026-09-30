//! Calls through followed dependency modules, composed from module summaries.
//!
//! Invocation analysis follows explicit dependency paths (`require("./lib")`,
//! `import ... from "./lib.js"`) and nests each module's top level. A call from
//! the importing program into an exported function of such a module applies
//! that function's summary at the call site with the caller's arguments, then
//! follows the summary's own call edges into same-module functions and further
//! followed dependencies. Uncalled exports never contribute effects.
//!
//! PHP includes and Ruby requires define global functions instead of exports:
//! a bare call resolves to the one function of that name defined by a module
//! the same launch loaded. Competing definitions stay unresolved.
//!
//! Only edges this linker can bind exactly are followed. Receiver dispatch,
//! callbacks, lifecycle registrations, bare package imports, and globals remain
//! `unresolved_call` boundaries naming the callee; repository indexing owns
//! the complete linker.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference, Domain,
    ProvenanceKind, ProvenanceRef, ResourceExpr,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::module_summary::{CallEdge, FunctionEntry, ModuleSummary};
use crate::nest::Nest;
use crate::{Lang, ScopeKey, SemanticValue, SummaryBudget, ValueArgument};

/// Identifies one dependency request by where it was written.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DependencyRequestKey {
    /// Source namespace directory of the requesting module.
    pub source_cwd: Option<String>,
    pub language: &'static str,
    pub specifier: String,
}

/// A dependency module source admitted by a followed request, bound to the
/// exact bytes nested for its top-level execution.
pub(crate) struct FollowedDependency {
    /// The process launch whose dependency graph loaded this module.
    pub launch: effinterp_proto::ExecutionNodeRef,
    pub path: String,
    pub source: String,
    pub digest: String,
    pub lang: Lang,
}

/// Followed dependency sources and their module summaries for one invocation.
#[derive(Default)]
pub(crate) struct DependencyCalls {
    followed: RefCell<BTreeMap<DependencyRequestKey, Rc<FollowedDependency>>>,
    summaries: RefCell<HashMap<(String, String), Rc<ModuleSummary>>>,
    in_progress: RefCell<HashSet<(String, String)>>,
}

impl DependencyCalls {
    pub(crate) fn record_followed(
        &self,
        key: DependencyRequestKey,
        dependency: FollowedDependency,
    ) {
        self.followed.borrow_mut().insert(key, Rc::new(dependency));
    }

    /// Whether `launch` followed this request to an admitted source.
    pub(crate) fn is_followed(
        &self,
        key: &DependencyRequestKey,
        launch: effinterp_proto::ExecutionNodeRef,
    ) -> bool {
        self.followed(key)
            .is_some_and(|dependency| dependency.launch == launch)
    }

    fn followed(&self, key: &DependencyRequestKey) -> Option<Rc<FollowedDependency>> {
        self.followed.borrow().get(key).cloned()
    }
}

/// Apply a global function defined by a module this launch loaded (a PHP
/// include or Ruby require). False when no loaded module defines `function`
/// or more than one does.
pub(crate) fn apply_global_dependency_call(
    builder: &mut PlanBuilder,
    nest: &Nest,
    language: &'static str,
    function: &str,
    arguments: &[ValueArgument],
    call_site: ProvenanceRef,
) -> bool {
    let launch = builder.current_dependency_launch();
    let loaded: Vec<Rc<FollowedDependency>> = nest
        .dependency_calls
        .followed
        .borrow()
        .iter()
        .filter(|(key, dependency)| key.language == language && dependency.launch == launch)
        .map(|(_, dependency)| Rc::clone(dependency))
        .collect();
    let mut definitions = Vec::new();
    for dependency in loaded {
        if definitions
            .iter()
            .any(|(defined, _): &(Rc<FollowedDependency>, _)| defined.path == dependency.path)
        {
            continue;
        }
        let Some(summary) = module_summary(builder, nest, &dependency) else {
            return false;
        };
        if summary.functions.iter().any(|entry| entry.name == function) {
            definitions.push((dependency, summary));
        }
    }
    let [(dependency, summary)] = definitions.as_slice() else {
        return false;
    };
    let entry = summary
        .functions
        .iter()
        .find(|entry| entry.name == function)
        .expect("definition was found above");
    apply_function(
        builder, nest, dependency, summary, entry, arguments, call_site, false,
    );
    true
}

/// Whether a dependency specifier names a path rather than a package search.
pub(crate) fn is_path_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../") || specifier.starts_with('/')
}

/// Apply `function` exported by the followed dependency `key` with positional
/// or named `arguments`. `host_environment` resolves the environment values
/// the function reads to the ones the current execution sees; the caller
/// withholds it when its program can rewrite them first. False when the
/// request was not followed or the name is not an exported function; the
/// caller then keeps its unresolved-call boundary.
pub(crate) fn apply_dependency_call(
    builder: &mut PlanBuilder,
    nest: &Nest,
    key: &DependencyRequestKey,
    function: &str,
    arguments: &[ValueArgument],
    call_site: ProvenanceRef,
    host_environment: bool,
) -> bool {
    let Some(dependency) = nest.dependency_calls.followed(key) else {
        return false;
    };
    let Some(summary) = module_summary(builder, nest, &dependency) else {
        return false;
    };
    let Some(entry) = exported_function(&summary, function) else {
        return false;
    };
    apply_function(
        builder,
        nest,
        &dependency,
        &summary,
        entry,
        arguments,
        call_site,
        host_environment,
    );
    true
}

fn module_summary(
    builder: &mut PlanBuilder,
    nest: &Nest,
    dependency: &FollowedDependency,
) -> Option<Rc<ModuleSummary>> {
    let key = (dependency.path.clone(), dependency.digest.clone());
    if let Some(summary) = nest.dependency_calls.summaries.borrow().get(&key) {
        return Some(Rc::clone(summary));
    }
    if nest.budget.timed_out() {
        builder.note_deadline();
        return None;
    }
    let summary = crate::module_summaries(
        &dependency.source,
        dependency.lang,
        &dependency.path,
        ScopeKey::Module {
            key: dependency.path.clone(),
        },
        &SummaryBudget::new(nest.limits.to_map()[SummaryBudget::limit_name(dependency.lang)]),
    );
    // Summary inference is not interruptible; work that crossed the deadline
    // is discarded rather than presented as a finished composition.
    if nest.budget.timed_out() {
        builder.note_deadline();
        return None;
    }
    let summary = Rc::new(summary);
    nest.dependency_calls
        .summaries
        .borrow_mut()
        .insert(key, Rc::clone(&summary));
    Some(summary)
}

fn exported_function<'s>(summary: &'s ModuleSummary, name: &str) -> Option<&'s FunctionEntry> {
    let local = summary
        .exported_definitions
        .iter()
        .find(|(exported, _)| exported == name)
        .map(|(_, local)| local.as_str())?;
    summary
        .functions
        .iter()
        .find(|function| function.name == local)
}

#[allow(clippy::too_many_arguments)]
fn apply_function(
    builder: &mut PlanBuilder,
    nest: &Nest,
    dependency: &Rc<FollowedDependency>,
    summary: &ModuleSummary,
    entry: &FunctionEntry,
    arguments: &[ValueArgument],
    call_site: ProvenanceRef,
    host_environment: bool,
) {
    let active = (dependency.path.clone(), entry.name.clone());
    if !nest
        .dependency_calls
        .in_progress
        .borrow_mut()
        .insert(active.clone())
    {
        unresolved_edge(
            builder,
            dependency,
            &entry.name,
            call_site,
            "recursive dependency call",
        );
        return;
    }
    let bindings = crate::bind_arguments(&entry.summary.params, arguments);
    let source = builder.node(
        ProvenanceKind::SourceInput {
            path: dependency.path.clone(),
            digest: dependency.digest.clone(),
        },
        &[call_site],
    );
    let limits = nest.limits.value_limits();
    let mut slots = Vec::with_capacity(entry.summary.effects.len());
    for (index, effect) in entry.summary.effects.iter().enumerate() {
        let mut visited = 0;
        let value = crate::substitute_value_counted(
            &SemanticValue::from(&effect.resource),
            &bindings,
            limits,
            &mut visited,
        );
        if !crate::nest::charge_analysis_steps(builder, nest.budget, visited.max(1), None) {
            break;
        }
        let mut specialized = effect.clone();
        crate::lower_effect_value(&mut specialized, &value);
        specialized.request_assurance = effinterp_proto::RequestAssurance::Conservative;
        specialized.provenance = vec![call_site, source];
        if host_environment {
            let before = specialized.provenance.len();
            resolve_environment(
                builder,
                nest,
                &mut specialized.resource,
                &mut specialized.provenance,
            );
            if specialized.provenance.len() > before {
                specialized.resource = effinterp_proto::normalize_resource(
                    specialized.resource,
                    effinterp_proto::PathPlatform::Posix,
                );
            }
        }
        // Once code this launch ran — an imported module's top level, a
        // function applied earlier, or the one calling this function — may
        // have written a variable, it may no longer hold the host's value, so
        // a path keeps it and names it as a dynamic source.
        if specialized.operation.domain() != "environment"
            && reads_rewritten_environment(builder, &specialized.resource)
        {
            let domain = Domain::new(specialized.operation.domain());
            builder.declare_coverage(domain.clone(), effinterp_proto::CoverageLevel::Partial);
            builder.boundary(Boundary {
                reason: BoundaryReason::DYNAMIC_SOURCE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: Some(specialized.resource.clone()),
                callee: None,
                domains: vec![domain],
                provenance: vec![call_site, source],
                limit: None,
                detail: Some(
                    "environment variable read after the program may have rewritten it".into(),
                ),
            });
        }
        for model in entry.summary.effect_models.get(index).into_iter().flatten() {
            let application = builder.node(
                ProvenanceKind::ModelApplication {
                    model: model.clone(),
                },
                &[source],
            );
            specialized.provenance.push(application);
        }
        slots.push(builder.effect(specialized));
    }
    crate::replay_transfers(builder, &entry.summary.transfers, &slots);
    for boundary in &entry.summary.boundaries {
        let mut boundary = boundary.clone();
        boundary.provenance = vec![call_site, source];
        builder.boundary(boundary);
    }
    for (domain, level) in &entry.summary.coverage {
        builder.declare_coverage(domain.clone(), *level);
    }
    for edge in &entry.calls {
        if nest.budget.timed_out() {
            builder.note_deadline();
            break;
        }
        let arguments: Vec<ValueArgument> = edge
            .arguments
            .iter()
            .map(|argument| ValueArgument {
                value: crate::substitute_value(
                    &parameter_argument(&argument.value),
                    &bindings,
                    limits,
                ),
                ..argument.clone()
            })
            .collect();
        if let Some(condition) = edge.condition.clone() {
            builder.push_condition(condition);
        }
        follow_edge(
            builder,
            nest,
            dependency,
            summary,
            edge,
            &arguments,
            source,
            host_environment,
        );
        if edge.condition.is_some() {
            builder.pop_condition();
        }
    }
    nest.dependency_calls
        .in_progress
        .borrow_mut()
        .remove(&active);
}

/// Summaries record a forwarded parameter as a parameter-typed object; as a
/// call argument it is the caller's parameter value itself.
fn parameter_argument(value: &SemanticValue) -> SemanticValue {
    match value.as_object() {
        Some(object) if object.properties.is_empty() => match &object.identity {
            crate::ObjectIdentity::Parameter { name, .. } => {
                SemanticValue::from(&effinterp_proto::ResourceExpr::Parameter {
                    name: name.clone(),
                })
            }
            _ => value.clone(),
        },
        _ => value.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn follow_edge(
    builder: &mut PlanBuilder,
    nest: &Nest,
    dependency: &Rc<FollowedDependency>,
    summary: &ModuleSummary,
    edge: &CallEdge,
    arguments: &[ValueArgument],
    site: ProvenanceRef,
    host_environment: bool,
) {
    if edge.receiver.is_some() || edge.dynamic_target || edge.lifecycle_registration {
        unresolved_edge(
            builder,
            dependency,
            &edge.callee,
            site,
            "call to unresolved dependency callee",
        );
        return;
    }
    let (head, member) = match edge.callee.split_once('.') {
        Some((head, member)) => (head, Some(member)),
        None => (edge.callee.as_str(), None),
    };
    if member.is_none() {
        // A JavaScript callee bound to a function of this module names its
        // body; a definition that was not summarized stays unresolved.
        let local = match edge.callee_span {
            Some(span) => summary
                .functions
                .iter()
                .find(|function| function.lexical_span == Some(span)),
            None if summary
                .functions
                .iter()
                .all(|function| function.lexical_span.is_none()) =>
            {
                summary
                    .functions
                    .iter()
                    .find(|function| function.name == head)
            }
            None => None,
        };
        if let Some(local) = local {
            // Ruby summaries already inline same-file calls into their effects.
            if dependency.lang != Lang::Ruby {
                apply_function(
                    builder,
                    nest,
                    dependency,
                    summary,
                    local,
                    arguments,
                    site,
                    host_environment,
                );
            }
            return;
        }
        if edge.callee_span.is_some() {
            unresolved_edge(
                builder,
                dependency,
                &edge.callee,
                site,
                "call to unsummarized dependency callee",
            );
            return;
        }
    }
    let global = match dependency.lang {
        Lang::Php => Some("php"),
        Lang::Ruby => Some("ruby"),
        _ => None,
    };
    if let Some(language) = global
        && apply_global_dependency_call(builder, nest, language, &edge.callee, arguments, site)
    {
        return;
    }
    let imported = summary
        .imports
        .iter()
        .chain(&summary.scoped_imports)
        .find(|binding| binding.local == head)
        .and_then(|binding| {
            let function = match (&binding.imported, member) {
                (Some(imported), None) => imported.clone(),
                (None, Some(member)) if !member.contains('.') => member.to_string(),
                _ => return None,
            };
            is_path_specifier(&binding.module).then(|| {
                (
                    DependencyRequestKey {
                        source_cwd: Some(crate::paths::parent_dir(&dependency.path)),
                        language: match dependency.lang {
                            Lang::Ruby => "ruby",
                            _ => "js",
                        },
                        specifier: binding.module.clone(),
                    },
                    function,
                )
            })
        });
    if let Some((key, function)) = imported
        && apply_dependency_call(
            builder,
            nest,
            &key,
            &function,
            arguments,
            site,
            host_environment,
        )
    {
        return;
    }
    unresolved_edge(
        builder,
        dependency,
        &edge.callee,
        site,
        "call to unresolved dependency callee",
    );
}

/// Replace each environment reference in a summarized resource with the
/// exact value the current execution sees, tracing it to where that value was
/// set or to the host context.
fn resolve_environment(
    builder: &mut PlanBuilder,
    nest: &Nest,
    resource: &mut ResourceExpr,
    provenance: &mut Vec<ProvenanceRef>,
) {
    match resource {
        ResourceExpr::Environment { name } => {
            if builder.launch_may_have_written_environment(name) {
                return;
            }
            let Some(value) = nest
                .environment_value(name)
                .filter(|value| !matches!(value, ResourceExpr::Unresolved { .. }))
            else {
                return;
            };
            provenance.push(nest.current_environment_node(name).unwrap_or_else(|| {
                builder.node(
                    ProvenanceKind::HostContext {
                        name: format!("env.{name}"),
                    },
                    &[],
                )
            }));
            *resource = value;
        }
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            for part in parts {
                resolve_environment(builder, nest, part, provenance);
            }
        }
        ResourceExpr::Property { base, .. } => resolve_environment(builder, nest, base, provenance),
        _ => {}
    }
}

fn reads_rewritten_environment(builder: &PlanBuilder, resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Environment { name } => builder.launch_may_have_written_environment(name),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => parts
            .iter()
            .any(|part| reads_rewritten_environment(builder, part)),
        ResourceExpr::Property { base, .. } => reads_rewritten_environment(builder, base),
        _ => false,
    }
}

fn unresolved_edge(
    builder: &mut PlanBuilder,
    dependency: &FollowedDependency,
    callee: &str,
    site: ProvenanceRef,
    detail: &str,
) {
    builder.global_opacity(effinterp_proto::CoverageLevel::Partial);
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRESOLVED_CALL,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: Some(CalleeReference {
            module: dependency.path.clone(),
            symbol: callee.to_string(),
        }),
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![site],
        limit: None,
        detail: Some(format!("{detail} {callee}")),
    });
}
