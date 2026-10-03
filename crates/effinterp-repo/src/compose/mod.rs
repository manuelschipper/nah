//! Cross-file effect composition.
//!
//! Starting from a set of root call edges (an entrypoint's top-level calls),
//! resolve each callee through the importing file's imports to a function in
//! another file, substitute the caller's argument expressions into that
//! function's parameterized summary, and recurse into its own calls — so an
//! entrypoint's effects trace through user code across files.
//!
//! Termination is guaranteed: a per-path cycle guard breaks recursion, a global
//! effect budget and call-depth bound cap total work, and a resource-expression
//! depth cap widens a growing symbolic path (deep recursion) to an unresolved
//! family rather than an unbounded tree. Every callee that cannot be resolved
//! (external package, dynamic dispatch, unmapped module) becomes an explicit
//! cross-module boundary, never a silent omission.

use crate::dispatch::DispatchVia;
use crate::index::RepositoryLimits;
use crate::launch::{is_process_template, specialize_process_template_with_bindings};
use crate::linker::Resolution;
use crate::module::{ModuleFile, ModuleRegistry};
use accumulation::{
    BoundaryCollection, ComposedBoundaryKey, RecursiveOccurrences, finalize,
    push_composed_boundary, push_composed_effect, push_composed_effect_slot,
    remove_composed_occurrence, replay_summary_transfers,
};
pub use budget::ComposeBudget;
pub(crate) use budget::cap_depth;
use budget::{
    all_domains, charge_compose_step, check_composition_depth, owned_domains, reserve_effect,
};
use control_discharge::{ControlOwner, control_requirements, evaluate_flow};
use effinterp_engine::{
    Assurance, CallEdge, ControlFact, ExternalCall, ImportBinding, ObjectIdentity, Requirements,
    ResolvedObject, SemanticValue, SemanticValueKind, SigRole, TransferBinding, TypeRef,
    ValueArgument, ValueOrigin, canonical_rust_std_type, contains_callable,
    python_external_method_effects, substitute_value,
};
use effinterp_proto::{
    BoundaryReason, CalleeReference, CoverageLevel, Effect, Modality, PathPlatform, ResourceExpr,
    normalize_resource,
};
use function::{
    enter_fn_args, enter_function, enter_function_with_assurance, follow_callable_value,
};
use instance::{
    bind_resolved_constructor, class_entry, instance_attrs, resolve_exact_class, resolve_instance,
    resolve_obj_args, resolve_runtime_value, resolved_object_value,
};
use lifecycle::{LifecycleState, activate_lifecycle, apply_lifecycle, lifecycle_match};
use memo::{MemoKey, MemoizedWalk};
use module_execution::{execute_imports, execution_reachable, push_unseen_file};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

mod accumulation;
mod budget;
mod control_discharge;
mod function;
mod instance;
mod lifecycle;
mod memo;
mod module_execution;

/// Exact callable bound to a function parameter.
#[derive(Debug, Clone)]
enum BoundCallable {
    Function { file: String, function: String },
    Class(ResolvedObject),
    External { module: String, member: String },
}

/// One composition walk in progress: the call path and stack that reached the
/// current function, its instance typing, and the composition being built.
struct CompositionWalk<'a> {
    registry: &'a ModuleRegistry,
    linker: &'a dyn crate::linker::Linker,
    out: &'a mut Composition,
    path: Vec<String>,
    stack: Vec<(String, String)>,
    env: InstanceEnv,
    assurance: Assurance,
}

impl<'a> CompositionWalk<'a> {
    fn run<R>(
        registry: &'a ModuleRegistry,
        file: &ModuleFile,
        out: &'a mut Composition,
        state: (&[String], &mut Vec<(String, String)>, &mut InstanceEnv),
        run: impl FnOnce(&mut CompositionWalk<'a>) -> R,
    ) -> R {
        let (path, stack, env) = state;
        let assurance = out.walk_assurance;
        let mut walk = CompositionWalk {
            registry,
            linker: registry.linker(file.lang),
            out,
            path: path.to_vec(),
            stack: std::mem::take(stack),
            env: std::mem::take(env),
            assurance,
        };
        let result = run(&mut walk);
        *stack = walk.stack;
        *env = walk.env;
        result
    }
}

type Callbacks = HashMap<String, BoundCallable>;

/// Instance typing for one entered function: the receiver instance, the
/// receiver's `self.<attr>` classes, instance-typed parameters (bound from the
/// caller's `obj_args`), and locals typed from followed calls' returned
/// instances. Everything here has unambiguous constructor provenance; an
/// untyped name simply never dispatches.
#[derive(Debug, Clone, Default)]
struct InstanceEnv {
    receiver: Option<ResolvedObject>,
    self_attrs: HashMap<String, ResolvedObject>,
    params: HashMap<String, ResolvedObject>,
    vars: HashMap<String, ResolvedObject>,
    values: HashMap<String, SemanticValue>,
}

/// Receiver context handed to an entered function.
#[derive(Debug, Clone, Default)]
struct ReceiverContext {
    receiver: Option<ResolvedObject>,
    self_attrs: HashMap<String, ResolvedObject>,
}

/// An effect produced by composing across files, with the cross-file path that
/// reached it (e.g. `["app.py", "util.py:wipe"]`) and the file it originates in.
#[derive(Debug, Clone)]
struct EffectOccurrence {
    pub effect: Effect,
    pub source_file: String,
    /// The chain of `file` / `file:function` steps from the entrypoint.
    pub path: Vec<String>,
    pub assurance: Assurance,
    pub via_dispatch: Option<DispatchVia>,
}

/// A cross-file transition that could not be resolved, so the effects beyond it
/// are unknown. Recorded rather than dropped.
#[derive(Debug, Clone)]
struct BoundaryOccurrence {
    pub class: effinterp_proto::BoundaryClass,
    pub reason: BoundaryReason,
    pub detail: String,
    /// The defining summary and imported callee for a copied frontend boundary.
    pub source_file: Option<String>,
    pub callee: Option<CalleeReference>,
    pub domains: Vec<String>,
    pub affected_resource: Option<ResourceExpr>,
    pub limit: Option<String>,
    pub path: Vec<String>,
    pub via_dispatch: Option<DispatchVia>,
}

/// A distinct composed effect; its evidence lives in occurrence rows.
#[derive(Debug, Clone)]
pub struct ComposedEffect {
    pub effect: Effect,
    pub occurrences: u32,
    // Includes omitted occurrences so removing retained evidence keeps the summary exact.
    pub(crate) unconditional_occurrences: u32,
}

/// Coalesced boundary evidence with at most four shortest, then lexical paths.
#[derive(Debug, Clone)]
pub struct ComposedBoundary {
    pub class: effinterp_proto::BoundaryClass,
    pub reason: BoundaryReason,
    pub detail: String,
    pub source_file: Option<String>,
    pub callee: Option<CalleeReference>,
    pub domains: Vec<String>,
    pub affected_resource: Option<ResourceExpr>,
    pub limit: Option<String>,
    pub via_dispatch: Option<DispatchVia>,
    /// Distinct path-keyed rows represented by this boundary.
    pub occurrences: u32,
    pub exemplar_paths: Vec<Vec<String>>,
}

impl From<BoundaryOccurrence> for ComposedBoundary {
    fn from(boundary: BoundaryOccurrence) -> Self {
        Self {
            class: boundary.class,
            reason: boundary.reason,
            detail: boundary.detail,
            source_file: boundary.source_file,
            callee: boundary.callee,
            domains: boundary.domains,
            affected_resource: boundary.affected_resource,
            limit: boundary.limit,
            via_dispatch: boundary.via_dispatch,
            occurrences: 1,
            exemplar_paths: vec![boundary.path],
        }
    }
}

/// One causally distinct occurrence of an entry in [`Composition::effects`].
#[derive(Debug, Clone)]
pub struct ComposedOccurrence {
    pub effect: usize,
    /// Original guard for this call instance, before the identity summary widens it.
    pub condition: Option<effinterp_proto::Condition>,
    pub source_file: String,
    pub path: Vec<String>,
    pub assurance: Assurance,
    pub via_dispatch: Option<DispatchVia>,
}

impl ComposedOccurrence {
    fn evidence(&self, effects: &[ComposedEffect]) -> EffectOccurrence {
        EffectOccurrence {
            effect: Effect {
                condition: self.condition.clone(),
                ..effects[self.effect].effect.clone()
            },
            source_file: self.source_file.clone(),
            path: self.path.clone(),
            assurance: self.assurance,
            via_dispatch: self.via_dispatch.clone(),
        }
    }
}

/// A frontend unresolved-call boundary superseded by repository composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCall {
    pub source_file: String,
    pub callee: CalleeReference,
}

// The boundary detail identifies the decorated function, so a closed stack on
// one function cannot prevent retraction for another using the same decorator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedDecorator {
    pub source_file: String,
    pub callee: CalleeReference,
    pub function: String,
}

impl ResolvedDecorator {
    pub(crate) fn matches_boundary(
        &self,
        source_file: &str,
        callee: Option<&CalleeReference>,
        detail: Option<&str>,
    ) -> bool {
        let written = if self.callee.module.is_empty() {
            self.callee.symbol.clone()
        } else {
            format!("{}.{}", self.callee.module, self.callee.symbol)
        };
        self.source_file == source_file
            && callee == Some(&self.callee)
            && detail == Some(format!("decorator {written} on {}", self.function).as_str())
    }
}

/// One contributor's callee path and the coverage it reported per domain.
type CoverageSegment = (Vec<String>, Vec<(String, CoverageLevel)>);

/// The result of composing one entrypoint across files.
#[derive(Debug, Clone)]
pub struct Composition {
    pub effects: Vec<ComposedEffect>,
    /// Every causally distinct effect occurrence before display deduplication.
    pub occurrence_effects: Vec<ComposedOccurrence>,
    /// Source-to-destination transfer pairings over `occurrence_effects` slots.
    /// Each entry is recorded where a summary's own binding was replayed, so a
    /// cross-file helper that copies or renames keeps its pairing.
    pub transfers: Vec<TransferBinding>,
    pub boundaries: Vec<ComposedBoundary>,
    /// Entrypoint-file occurrences the plan already carries, with the modality
    /// the repository proof reached for them. The single-file plan cannot
    /// discharge an import it could not resolve, so its own necessity is
    /// weaker than what this composition knows; these let the surface publish
    /// one conclusion per occurrence instead of two views of different
    /// strength. Never a row of its own.
    pub local_necessity: Vec<Effect>,
    pub resolved_calls: Vec<ResolvedCall>,
    /// Decorator identities proven transparent for an entered function.
    pub resolved_decorators: Vec<ResolvedDecorator>,
    unresolved_calls: Vec<ResolvedCall>,
    pub coverage: Vec<(String, CoverageLevel)>,
    // Temporary contributor evidence, folded into coverage and boundaries at finalization.
    coverage_segments: Vec<CoverageSegment>,
    /// Files whose summaries contributed — the entrypoint's dependency set,
    /// used for incremental invalidation.
    pub deps: Vec<String>,
    /// Total effect occurrences, including evidence omitted by the occurrence cap.
    pub occurrences: usize,
    pub budget: ComposeBudget,
    memo: HashMap<MemoKey, MemoizedWalk>,
    /// Recursion truncations observed while walking, including boundaries
    /// suppressed by global boundary deduplication.
    recursion_truncations: u64,
    effect_positions: HashMap<effinterp_proto::EffectId, usize>,
    boundary_keys: HashMap<ComposedBoundaryKey, usize>,
    boundary_paths: HashMap<ComposedBoundaryKey, HashSet<Vec<String>>>,
    memo_boundaries: Vec<BoundaryCollection>,
    dep_keys: HashSet<String>,
    /// Modules whose top level has already run (import semantics: once).
    executed: HashSet<String>,
    processed_functions: HashSet<(String, String)>,
    lifecycle: LifecycleState,
    walk_assurance: Assurance,
    walk_via_dispatch: Option<DispatchVia>,
    walk_condition: Option<effinterp_proto::Condition>,
    walk_call_instance: Option<String>,
    boundary_call: Option<(Vec<String>, String)>,
    force_may: bool,
    /// Every call on the current path is reached by each successful completion
    /// of the entrypoint, so an occurrence its callee requires is required.
    required: bool,
    /// An exception from this callable can still complete the entry normally.
    accepts_throw: bool,
    control_requirements: HashMap<(String, ControlOwner), Requirements>,
    recursive_round: bool,
    recursive_occurrences: Vec<RecursiveOccurrences>,
    recursive_dispatch_exhaustive: bool,
    recursive_groups: HashMap<(String, String), function::RecursiveGroup>,
}

impl Default for Composition {
    fn default() -> Self {
        Self::with_limits(RepositoryLimits::default())
    }
}

impl Composition {
    fn with_limits(limits: RepositoryLimits) -> Self {
        Self {
            effects: Vec::new(),
            occurrence_effects: Vec::new(),
            transfers: Vec::new(),
            boundaries: Vec::new(),
            local_necessity: Vec::new(),
            resolved_calls: Vec::new(),
            resolved_decorators: Vec::new(),
            unresolved_calls: Vec::new(),
            coverage: Vec::new(),
            coverage_segments: Vec::new(),
            deps: Vec::new(),
            occurrences: 0,
            budget: ComposeBudget {
                limits,
                steps: 0,
                saturated: None,
                reported_limits: HashSet::new(),
            },
            memo: HashMap::new(),
            recursion_truncations: 0,
            effect_positions: HashMap::new(),
            boundary_keys: HashMap::new(),
            boundary_paths: HashMap::new(),
            memo_boundaries: Vec::new(),
            dep_keys: HashSet::new(),
            executed: HashSet::new(),
            processed_functions: HashSet::new(),
            lifecycle: LifecycleState::default(),
            walk_assurance: Assurance::Exact,
            walk_via_dispatch: None,
            walk_condition: None,
            walk_call_instance: None,
            boundary_call: None,
            force_may: false,
            required: false,
            accepts_throw: false,
            control_requirements: HashMap::new(),
            recursive_round: false,
            recursive_occurrences: Vec::new(),
            recursive_dispatch_exhaustive: true,
            recursive_groups: HashMap::new(),
        }
    }

    /// Evidence omitted by the occurrence cap has a count but no claimed origin.
    pub(crate) fn effect_evidence(
        &self,
    ) -> impl Iterator<Item = (Effect, Option<&ComposedOccurrence>, u32)> {
        let mut retained = vec![0; self.effects.len()];
        for occurrence in &self.occurrence_effects {
            retained[occurrence.effect] += 1;
        }
        self.occurrence_effects
            .iter()
            .map(|occurrence| {
                let effect = Effect {
                    condition: occurrence.condition.clone(),
                    ..self.effects[occurrence.effect].effect.clone()
                };
                (effect, Some(occurrence), 1)
            })
            .chain(
                self.effects
                    .iter()
                    .zip(retained)
                    .filter_map(|(effect, retained)| {
                        (effect.occurrences > retained).then_some((
                            {
                                let mut summary = effect.effect.clone();
                                if summary
                                    .condition
                                    .as_ref()
                                    .is_some_and(effinterp_proto::Condition::is_widened)
                                {
                                    summary.request_assurance =
                                        effinterp_proto::RequestAssurance::Conservative;
                                }
                                summary
                            },
                            None,
                            effect.occurrences - retained,
                        ))
                    }),
            )
    }

    /// Deterministic estimate of bytes retained by one composition.
    pub fn retained_bytes(&self) -> u64 {
        let path_bytes =
            |path: &[String]| path.iter().map(|step| step.len() as u64 + 32).sum::<u64>();
        let dispatch_bytes = |dispatch: &Option<DispatchVia>| {
            dispatch.as_ref().map_or(0, |dispatch| {
                32 + dispatch.model.len() as u64
                    + path_bytes(&dispatch.registration_path)
                    + path_bytes(&dispatch.dispatch_path)
            })
        };
        let effect_bytes = self
            .effects
            .iter()
            .map(|effect| 32 + effinterp_proto::canonical_json(&effect.effect).len() as u64);
        let occurrence_bytes = self.occurrence_effects.iter().map(|occurrence| {
            32 + std::mem::size_of::<usize>() as u64
                + occurrence.source_file.len() as u64
                + path_bytes(&occurrence.path)
                + dispatch_bytes(&occurrence.via_dispatch)
                + effinterp_proto::canonical_json(&occurrence.condition).len() as u64
        });
        let boundary_bytes = self.boundaries.iter().map(|boundary| {
            32 + boundary.reason.as_str().len() as u64
                + boundary.detail.len() as u64
                + boundary
                    .source_file
                    .as_ref()
                    .map_or(0, |source_file| source_file.len() as u64)
                + boundary.callee.as_ref().map_or(0, |callee| {
                    effinterp_proto::canonical_json(callee).len() as u64
                })
                + boundary
                    .domains
                    .iter()
                    .map(|domain| domain.len() as u64)
                    .sum::<u64>()
                + boundary
                    .limit
                    .as_ref()
                    .map_or(0, |limit| limit.len() as u64)
                + boundary
                    .exemplar_paths
                    .iter()
                    .map(|path| path_bytes(path))
                    .sum::<u64>()
                + dispatch_bytes(&boundary.via_dispatch)
        });
        effect_bytes
            .chain(occurrence_bytes)
            .chain(boundary_bytes)
            .chain(self.resolved_calls.iter().map(|call| {
                32 + call.source_file.len() as u64
                    + effinterp_proto::canonical_json(&call.callee).len() as u64
            }))
            .chain(self.deps.iter().map(|dep| dep.len() as u64 + 32))
            .sum()
    }
}

/// Compose an entrypoint file's cross-file effects: every function defined in
/// the file has its call edges followed into the functions they reach (in this
/// or another file), so the composition captures the file's callable reach
/// across module boundaries. A function's own in-file direct effects remain the
/// single-file plan's responsibility; composition adds what crossing a call
/// resolves to.
#[cfg(test)]
pub(crate) fn compose(
    registry: &ModuleRegistry,
    entry: &ModuleFile,
    entry_function: Option<&str>,
) -> Composition {
    compose_inner(
        registry,
        entry,
        entry_function,
        None,
        true,
        &[],
        RepositoryLimits::default(),
    )
}

pub(crate) fn compose_with_package_init(
    registry: &ModuleRegistry,
    entry: &ModuleFile,
    entry_function: Option<&str>,
    registration: Option<&effinterp_engine::Registration>,
    package_inits: &[String],
    limits: RepositoryLimits,
) -> Composition {
    let package_inits = package_inits
        .iter()
        .filter_map(|path| registry.files.get(path).map(|file| file.as_ref()))
        .collect::<Vec<_>>();
    compose_inner(
        registry,
        entry,
        entry_function,
        registration,
        true,
        &package_inits,
        limits,
    )
}

pub(crate) fn compose_callable(
    registry: &ModuleRegistry,
    entry: &ModuleFile,
    limits: RepositoryLimits,
) -> Composition {
    compose_inner(registry, entry, None, None, false, &[], limits)
}

fn compose_inner(
    registry: &ModuleRegistry,
    entry: &ModuleFile,
    entry_function: Option<&str>,
    registration: Option<&effinterp_engine::Registration>,
    package_roots: bool,
    package_inits: &[&ModuleFile],
    limits: RepositoryLimits,
) -> Composition {
    let mut out = Composition::with_limits(limits);
    let mut stack: Vec<(String, String)> = Vec::new();
    // The module's own top-level execution is the entrypoint's real root — a
    // script that calls an imported function at module level is the common
    // case (and how an entrypoint reaches other files).
    let module_root = vec![entry.path.clone()];
    let no_callbacks = HashMap::new();
    // Importing a module executes its top level, and imports run before any of
    // the entrypoint's own code. `from ansible import constants` therefore runs
    // constants.py (and ansible/__init__.py) first — walking imports first also
    // keeps import-time effects ahead of the traversal budget.
    let entry_execution_roots = if package_roots {
        registry.linker(entry.lang).execution_roots(registry, entry)
    } else {
        Default::default()
    };
    let mut execution_roots: Vec<(&ModuleFile, Option<&str>)> = package_inits
        .iter()
        .map(|init| (*init, None))
        .collect::<Vec<_>>();
    execution_roots.extend(entry_execution_roots);
    if !package_inits.is_empty() {
        execution_roots.push((entry, None));
    }
    let mut root_files = Vec::new();
    for init in package_inits {
        push_unseen_file(&mut root_files, init);
    }
    push_unseen_file(&mut root_files, entry);
    for (file, _) in &execution_roots {
        push_unseen_file(&mut root_files, file);
    }
    for file in &root_files {
        out.executed.insert(file.path.clone());
        push_module_boundaries(file, &module_root, &mut out);
    }
    if package_roots {
        for file in &root_files {
            execute_imports(registry, file, &module_root, &mut stack, &mut out);
        }
    }
    // Main-guard calls run because this file IS the entrypoint; imported files'
    // main guards never run (execute_imports follows module_calls only).
    let mut module_env = InstanceEnv::default();
    // A top-level call is required when the module's successful completions
    // all reach it and the entrypoint-only statements can still succeed; a
    // main-guard call additionally needs the module to always reach its end.
    let entry_module = control_requirements(
        registry,
        entry,
        &ControlOwner::Module,
        &mut out,
        &module_root,
    );
    let entry_main =
        control_requirements(registry, entry, &ControlOwner::Main, &mut out, &module_root);
    let module_call_required = |file: &ModuleFile, index: usize| {
        file.path == entry.path
            && entry_module
                .on_success
                .contains(&ControlFact::Call(index as u32))
            && (entry_main.succeeds || entry_main.may_exit)
    };
    let main_call_required = |index: usize| {
        entry_module.succeeds
            && !entry_module.may_exit
            && entry_main
                .on_success
                .contains(&ControlFact::Call(index as u32))
    };
    if !execution_roots.is_empty() {
        for file in &root_files {
            if file.path != entry.path {
                push_module_effects(file, &module_root, &mut out);
            }
        }
        for (file, _) in execution_roots
            .iter()
            .filter(|(_, function)| function.is_none())
        {
            let mut env = InstanceEnv::default();
            for (index, edge) in file.summary.module_calls.iter().enumerate() {
                if edge_origin_function(edge).is_some_and(|name| !name.is_empty()) {
                    continue;
                }
                out.required = module_call_required(file, index);
                out.accepts_throw = !entry_module
                    .on_success
                    .contains(&ControlFact::CallSuccess(index as u32));
                CompositionWalk::run(
                    registry,
                    file,
                    &mut out,
                    (&module_root, &mut stack, &mut env),
                    |walk| follow_execution_root(walk, file, edge, &no_callbacks),
                );
                out.required = false;
            }
        }
        for (file, function) in execution_roots
            .iter()
            .filter_map(|(file, function)| function.map(|function| (*file, function)))
        {
            let mut env = InstanceEnv::default();
            let mut function_path = module_root.clone();
            function_path.push(format!("{}:{function}", file.path));
            if let Some(entry) = file.function(function) {
                if !entry.decorator_gate.is_empty() {
                    let edge = CallEdge {
                        callee: function.to_string(),
                        ..Default::default()
                    };
                    CompositionWalk::run(
                        registry,
                        file,
                        &mut out,
                        (&module_root, &mut stack, &mut env),
                        |walk| {
                            enter_function(
                                walk,
                                file,
                                file,
                                function,
                                &edge,
                                ReceiverContext::default(),
                                false,
                            )
                        },
                    );
                    continue;
                }
                push_root_effects(registry, file, entry, &module_root, &mut out);
            }
            for edge in &file.summary.module_calls {
                if edge_origin_function(edge) != Some(function) {
                    continue;
                }
                CompositionWalk::run(
                    registry,
                    file,
                    &mut out,
                    (&function_path, &mut stack, &mut env),
                    |walk| follow_execution_root(walk, file, edge, &no_callbacks),
                );
            }
        }
        for (index, edge) in entry
            .summary
            .main_calls
            .iter()
            .enumerate()
            .filter(|_| registration.is_none())
        {
            out.required = main_call_required(index);
            out.accepts_throw = !entry_main
                .on_success
                .contains(&ControlFact::CallSuccess(index as u32));
            CompositionWalk::run(
                registry,
                entry,
                &mut out,
                (&module_root, &mut stack, &mut module_env),
                |walk| follow(walk, entry, edge, &no_callbacks),
            );
            out.required = false;
        }
    } else {
        let roots = entry
            .summary
            .module_calls
            .iter()
            .enumerate()
            .map(|(index, edge)| {
                (
                    edge,
                    module_call_required(entry, index),
                    !entry_module
                        .on_success
                        .contains(&ControlFact::CallSuccess(index as u32)),
                )
            })
            .chain(
                entry
                    .summary
                    .main_calls
                    .iter()
                    .filter(|_| registration.is_none())
                    .enumerate()
                    .map(|(index, edge)| {
                        (
                            edge,
                            main_call_required(index),
                            !entry_main
                                .on_success
                                .contains(&ControlFact::CallSuccess(index as u32)),
                        )
                    }),
            )
            .collect::<Vec<_>>();
        for (edge, required, accepts_throw) in roots {
            out.required = required;
            out.accepts_throw = accepts_throw;
            CompositionWalk::run(
                registry,
                entry,
                &mut out,
                (&module_root, &mut stack, &mut module_env),
                |walk| follow(walk, entry, edge, &no_callbacks),
            );
            out.required = false;
        }
    }
    if package_roots
        && registration.is_none()
        && let Some(main) = entry.function("main")
        && main.decorator_gate.is_empty()
    {
        let path = vec![format!("{}:main", entry.path)];
        for effect in main
            .summary
            .effects
            .iter()
            .filter(|effect| is_process_template(effect))
        {
            push_specialized_process_effects(
                effect,
                &module_env.values,
                entry,
                &path,
                &mut out,
                registry.value_limits(),
            );
        }
    }
    // A console-script entrypoint (`pkg.mod:func`) imports the module and then
    // calls `func` — an execution root the file's own top level never names.
    // Entered with effects collected: the single-file plan does not call it.
    let selected: Vec<&str> = registration
        .map(|registration| {
            registration
                .selected_handlers
                .iter()
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_else(|| {
            entry_function
                .filter(|name| entry.function(name).is_some())
                .into_iter()
                .collect()
        });
    for name in selected {
        if registration.is_some()
            && entry.function(name).is_none()
            && matches!(
                registry
                    .linker(entry.lang)
                    .resolve_callee(registry, entry, name),
                Resolution::Unknown
            )
        {
            push_linker_boundary(
                &mut out,
                &[entry.path.clone(), format!("{}:{name}", entry.path)],
                BoundaryReason::DYNAMIC_DISPATCH,
                format!("registration handler {name:?} has no statically resolved target"),
            );
            continue;
        }
        let edge = CallEdge {
            callee: name.to_string(),
            // FastAPI executes async endpoints as part of request dispatch.
            awaited: registration.is_some_and(|registration| {
                matches!(
                    registration.kind,
                    effinterp_engine::RegistrationKind::Route { .. }
                )
            }),
            ..Default::default()
        };
        CompositionWalk::run(
            registry,
            entry,
            &mut out,
            (&module_root, &mut stack, &mut module_env),
            |walk| {
                if registration.is_some() {
                    follow_execution_root(walk, entry, &edge, &no_callbacks);
                } else {
                    enter_function(
                        walk,
                        entry,
                        entry,
                        name,
                        &edge,
                        ReceiverContext::default(),
                        false,
                    );
                }
            },
        );
    }
    // Only functions actually reachable from execution contribute to the
    // entrypoint's execution surface — following every defined function would
    // reintroduce source-presence semantics (an uncalled function's cross-file
    // effect wrongly attributed to the entrypoint). A callable-oriented query
    // is a separate surface, not this one.
    let mut reachable: Vec<String> = if registration.is_some() {
        Vec::new()
    } else {
        execution_reachable(entry).into_iter().collect()
    };
    reachable.sort();
    for name in reachable {
        // A callerless pass cannot add another instance of a body already handled at its call sites.
        if out
            .processed_functions
            .contains(&(entry.path.clone(), name.clone()))
        {
            continue;
        }
        let Some(func) = entry.function(&name) else {
            continue;
        };
        let path = vec![format!("{}:{}", entry.path, func.name)];
        let mut env = InstanceEnv::default();
        for edge in &func.calls {
            // A call through this function's own parameter is bound only at a
            // call site: this callerless walk knows nothing about its target,
            // and every reachable call site is walked with its bindings.
            if edge.dynamic_target && func.summary.params.contains(&edge.callee) {
                continue;
            }
            CompositionWalk::run(
                registry,
                entry,
                &mut out,
                (&path, &mut stack, &mut env),
                |walk| follow(walk, entry, edge, &no_callbacks),
            );
        }
        for effect in func
            .summary
            .effects
            .iter()
            .filter(|effect| is_process_template(effect))
        {
            push_specialized_process_effects(
                effect,
                &env.values,
                entry,
                &path,
                &mut out,
                registry.value_limits(),
            );
        }
    }
    if out.budget.saturated.is_none() {
        activate_lifecycle(registry, &mut stack, &mut out);
    }
    finalize(&mut out);
    out
}

fn edge_origin_function(edge: &CallEdge) -> Option<&str> {
    match edge
        .results
        .first()
        .and_then(|result| result.value.evidence.origin.as_ref())
    {
        Some(effinterp_engine::ValueOrigin::Site { function, .. }) => Some(function),
        _ => None,
    }
}

fn push_root_effects(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    function: &effinterp_engine::FunctionEntry,
    path: &[String],
    out: &mut Composition,
) {
    if out.budget.saturated.is_some() {
        return;
    }
    let mut effect_path = path.to_vec();
    effect_path.push(format!("{}:{}", file.path, function.name));
    let bindings = registry.linker(file.lang).package_bindings(registry, file);
    let module = control_requirements(registry, file, &ControlOwner::Module, out, path);
    let mut required = BTreeSet::new();
    for (effect, call) in function
        .summary
        .control_flow
        .effects_at_calls()
        .filter(|_| path.first() == Some(&file.path))
    {
        if !charge_compose_step(out, path) {
            required.clear();
            break;
        }
        if let Some(edge) = function.calls.get(call as usize)
            && edge.call_site.is_some()
            && let Some(index) = file
                .summary
                .module_calls
                .iter()
                .position(|candidate| candidate == edge)
            && module.on_success.contains(&ControlFact::Call(index as u32))
        {
            required.insert(effect);
        }
    }
    for (slot, effect) in function.summary.effects.iter().enumerate() {
        if !reserve_effect(out, &effect_path) {
            break;
        }
        let mut effect = specialize_effect(effect, &bindings, registry.value_limits());
        if required.contains(&(slot as u32)) {
            effect.modality = effinterp_proto::Modality::MustOnSuccess;
        }
        let previous_required =
            std::mem::replace(&mut out.required, required.contains(&(slot as u32)));
        push_composed_effect(
            out,
            EffectOccurrence {
                effect,
                source_file: file.path.clone(),
                path: effect_path.clone(),
                assurance: out.walk_assurance,
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
        out.required = previous_required;
    }
}

fn specialize_effect(
    effect: &Effect,
    bindings: &HashMap<String, SemanticValue>,
    value_limits: effinterp_engine::ValueLimits,
) -> Effect {
    let mut effect = effect.clone();
    let value = SemanticValue::from(&effect.resource);
    let value = substitute_value(&value, bindings, value_limits);
    effinterp_engine::lower_effect_value(&mut effect, &value);
    let resource = normalize_resource(cap_depth(effect.resource.clone()), PathPlatform::Posix);
    if resource != effect.resource {
        effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
    }
    effect.resource = resource;
    effect
}

/// The root function's effects seen through its package's values, paired with
/// the effect the single-file frontend produced. The caller needs both halves:
/// the specialized effect is the conclusion, and the unspecialized one
/// identifies which occurrence of an identical unknown the package view
/// resolved.
pub(crate) fn go_root_effects(
    registry: &ModuleRegistry,
    file: &ModuleFile,
    function: &str,
    composition: &mut Composition,
) -> Vec<(Effect, Effect)> {
    if !registry.go_packages.contains_key(&file.path) {
        return Vec::new();
    }
    let owner = ControlOwner::Function(function.to_string());
    let Some(function) = file.function(function) else {
        return Vec::new();
    };
    let path = vec![file.path.clone()];
    let module = control_requirements(registry, file, &ControlOwner::Module, composition, &path);
    let plan_module = evaluate_flow(
        &file.summary.module_control_flow,
        &BTreeSet::new(),
        &BTreeMap::new(),
        file,
        composition,
        &path,
    );
    let required = control_requirements(registry, file, &owner, composition, &path);
    let bindings = registry.linker(file.lang).package_bindings(registry, file);
    function
        .summary
        .effects
        .iter()
        .enumerate()
        .map(|(slot, effect)| {
            let required = required
                .on_success
                .contains(&ControlFact::Effect(slot as u32));
            let mut plan = effect.clone();
            let mut resolved = specialize_effect(effect, &bindings, registry.value_limits());
            if required && plan_module.succeeds && !plan_module.may_exit {
                plan.modality = effinterp_proto::Modality::MustOnSuccess;
            }
            if required && module.succeeds && !module.may_exit {
                resolved.modality = effinterp_proto::Modality::MustOnSuccess;
            }
            (plan, resolved)
        })
        .collect()
}

fn follow_execution_root(
    walk: &mut CompositionWalk<'_>,
    file: &ModuleFile,
    edge: &CallEdge,
    callbacks: &Callbacks,
) {
    if !edge.callee.contains('.')
        && edge.receiver.is_none()
        && find_import(&file.summary, &edge.callee).is_none()
        && file.function(&edge.callee).is_some()
    {
        let (prior_condition, prior_instance) = bind_call_condition(walk.out, file, edge);
        enter_function(
            walk,
            file,
            file,
            &edge.callee,
            edge,
            ReceiverContext::default(),
            false,
        );
        walk.out.walk_condition = prior_condition;
        walk.out.walk_call_instance = prior_instance;
    } else {
        follow(walk, file, edge, callbacks);
    }
}

fn push_module_boundaries(file: &ModuleFile, path: &[String], out: &mut Composition) {
    for boundary in &file.summary.module_boundaries {
        push_composed_boundary(
            out,
            BoundaryOccurrence {
                class: boundary.class,
                reason: boundary.reason.clone(),
                detail: boundary.detail.clone().unwrap_or_default(),
                source_file: Some(file.path.clone()),
                callee: boundary.callee.clone(),
                domains: boundary
                    .domains
                    .iter()
                    .map(|domain| domain.0.clone())
                    .collect(),
                affected_resource: boundary.affected_resource.clone(),
                limit: boundary.limit.clone(),
                path: path.to_vec(),
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
    }
}

fn push_module_effects(file: &ModuleFile, path: &[String], out: &mut Composition) {
    if out.budget.saturated.is_some() {
        return;
    }
    push_module_boundaries(file, path, out);
    push_module_effect_list(file, path, out);
}

/// A module's own top-level effects, with the transfer pairings the frontend
/// recorded among them.
fn push_module_effect_list(file: &ModuleFile, path: &[String], out: &mut Composition) {
    let mut slots: Vec<Option<usize>> = Vec::with_capacity(file.summary.module_effects.len());
    for effect in &file.summary.module_effects {
        if !reserve_effect(out, path) {
            break;
        }
        let (_, occurrence) = push_composed_effect_slot(
            out,
            EffectOccurrence {
                effect: effect.clone(),
                source_file: file.path.clone(),
                path: path.to_vec(),
                assurance: out.walk_assurance,
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
        slots.push(occurrence);
    }
    replay_summary_transfers(out, &file.summary.module_transfers, &slots);
}

fn push_specialized_process_effects(
    effect: &Effect,
    bindings: &HashMap<String, SemanticValue>,
    source: &ModuleFile,
    path: &[String],
    out: &mut Composition,
    value_limits: effinterp_engine::ValueLimits,
) {
    if out.budget.saturated.is_some() {
        return;
    }
    let Some((specializations, widened)) =
        specialize_process_template_with_bindings(effect, bindings, value_limits)
    else {
        return;
    };
    if widened {
        push_composed_boundary(
            out,
            BoundaryOccurrence {
                class: effinterp_proto::BoundaryClass::Limit,
                reason: BoundaryReason::new("value_widened"),
                detail: "rust command candidate cardinality exceeded".to_string(),
                source_file: None,
                callee: None,
                domains: vec!["process".to_string()],
                affected_resource: None,
                limit: None,
                path: path.to_vec(),
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
        out.coverage
            .push(("process".to_string(), CoverageLevel::Partial));
    }
    for specialized in specializations {
        if !reserve_effect(out, path) {
            return;
        }
        push_composed_effect(
            out,
            EffectOccurrence {
                effect: specialized,
                source_file: source.path.clone(),
                path: path.to_vec(),
                assurance: out.walk_assurance,
                via_dispatch: out.walk_via_dispatch.clone(),
            },
        );
    }
}

/// Compose from an explicit set of root call edges evaluated in `entry` — the
/// composition primitive, used directly in tests with a hand-built registry.
#[cfg(test)]
pub fn compose_roots(
    registry: &ModuleRegistry,
    entry: &ModuleFile,
    root_label: &str,
    roots: &[CallEdge],
) -> Composition {
    let mut out = Composition::default();
    let mut stack: Vec<(String, String)> = Vec::new();
    let no_callbacks = HashMap::new();
    let mut env = InstanceEnv::default();
    for edge in roots {
        CompositionWalk::run(
            registry,
            entry,
            &mut out,
            (&[root_label.to_string()], &mut stack, &mut env),
            |walk| follow(walk, entry, edge, &no_callbacks),
        );
    }
    finalize(&mut out);
    out
}

fn is_constructor_fact(edge: &CallEdge) -> bool {
    if edge.result_bindings().next().is_some() {
        return edge.result_type().is_some();
    }
    match edge.result_type() {
        Some(effinterp_engine::TypeRef::Repo { name, .. }) => {
            edge.callee.rsplit('.').next() == Some(name.as_str())
        }
        Some(effinterp_engine::TypeRef::External { path }) => path.ends_with(&edge.callee),
        None => false,
    }
}

fn bind_call_condition(
    out: &mut Composition,
    importer: &ModuleFile,
    edge: &CallEdge,
) -> (Option<effinterp_proto::Condition>, Option<String>) {
    let prior_condition = out.walk_condition.clone();
    let prior_instance = out.walk_call_instance.clone();
    out.walk_call_instance = Some(effinterp_proto::stable_hash(
        effinterp_proto::CONDITION_CALL_HASH_DOMAIN,
        &(
            &prior_instance,
            &importer.path,
            &edge.call_site,
            &edge.callee,
        ),
    ));
    let mut guard = edge.condition.clone();
    if let (Some(guard), Some(instance)) = (&mut guard, &prior_instance) {
        guard.rebind(instance);
    }
    out.walk_condition =
        effinterp_proto::Condition::compose(prior_condition.iter().chain(guard.iter()));
    (prior_condition, prior_instance)
}

fn follow(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    callbacks: &Callbacks,
) {
    if !charge_compose_step(walk.out, &walk.path) {
        return;
    }
    let edge = substitute_edge_values(edge, &walk.env.values, walk.registry.value_limits());
    let (prior_condition, prior_instance) = bind_call_condition(walk.out, importer, &edge);
    let prior_boundary_call = walk.out.boundary_call.replace((
        walk.path.clone(),
        format!("{}:{}", importer.path, edge.callee),
    ));
    follow_inner(walk, importer, &edge, callbacks);
    walk.out.boundary_call = prior_boundary_call;
    walk.out.walk_condition = prior_condition;
    walk.out.walk_call_instance = prior_instance;
    // The callee may have written through an argument that handed it the
    // caller's own storage, so the caller's exact view of that binding — the
    // object a constructor bound, the value last assigned to it — does not
    // survive the call.
    for name in &edge.writes {
        walk.env.values.remove(name);
        walk.env.vars.remove(name);
        walk.env.params.remove(name);
    }
    bind_declared_result_values(
        walk.linker,
        &edge,
        &mut walk.env,
        walk.registry.value_limits(),
    );
}

fn substitute_edge_values(
    edge: &CallEdge,
    bindings: &HashMap<String, SemanticValue>,
    value_limits: effinterp_engine::ValueLimits,
) -> CallEdge {
    let mut edge = edge.clone();
    for argument in &mut edge.arguments {
        argument.value = substitute_value(&argument.value, bindings, value_limits);
    }
    for result in &mut edge.results {
        result.value = substitute_value(&result.value, bindings, value_limits);
    }
    edge
}

fn bind_declared_result_values(
    linker: &dyn crate::linker::Linker,
    edge: &CallEdge,
    env: &mut InstanceEnv,
    value_limits: effinterp_engine::ValueLimits,
) {
    for result in &edge.results {
        let Some(binding) = &result.binding else {
            continue;
        };
        if let SemanticValueKind::Symbol(symbol) = &result.value.kind {
            if let Some(value) = env.values.get(binding).cloned() {
                env.values.insert(symbol.clone(), value);
            }
            continue;
        }
        if !matches!(result.value.kind, SemanticValueKind::Unresolved { .. }) {
            env.values.insert(
                binding.clone(),
                linker.declared_result_value(result.value.clone(), value_limits),
            );
        }
    }
}

fn follow_inner(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    callbacks: &Callbacks,
) {
    let lifecycle_registers = apply_lifecycle(
        walk.registry,
        importer,
        edge,
        &walk.path,
        walk.out,
        &mut walk.env,
    );
    if lifecycle_registers && edge.lifecycle_registration {
        return;
    }
    if !charge_compose_step(walk.out, &walk.path) || !check_composition_depth(walk.out, &walk.path)
    {
        return;
    }
    let edge = CallEdge {
        condition: None,
        call_site: edge.call_site.clone(),
        callee: edge.callee.clone(),
        arguments: edge
            .arguments
            .iter()
            .map(|argument| ValueArgument {
                name: argument.name.clone(),
                index: argument.index,
                value: resolve_runtime_value(walk.registry, importer, &walk.env, &argument.value),
            })
            .collect(),
        receiver: edge
            .receiver
            .as_ref()
            .map(|receiver| resolve_runtime_value(walk.registry, importer, &walk.env, receiver)),
        results: edge.results.clone(),
        awaited: edge.awaited,
        effects_propagated: edge.effects_propagated,
        external_inert: edge.external_inert.clone(),
        lifecycle_registration: edge.lifecycle_registration,
        dynamic_target: edge.dynamic_target,
        callee_span: edge.callee_span,
        writes: edge.writes.clone(),
    };
    let edge = &edge;
    // A locally bound callee names no package symbol: only the value bound to
    // it may resolve the call.
    let constructor = (!edge.dynamic_target)
        .then(|| resolve_exact_class(walk.registry, importer, &edge.callee))
        .flatten();
    if walk.linker.is_constructor_fact(edge)
        || (walk.linker.constructor_result_is_instance(edge) && constructor.is_some())
    {
        if let Some(value) = constructor {
            bind_resolved_constructor(
                walk.registry,
                importer,
                value,
                edge,
                &mut walk.env,
                walk.out,
            );
            record_resolved_call(walk.registry, importer, edge, walk.out);
        } else {
            record_unresolved_call(walk.registry, importer, edge, walk.out);
        }
        return;
    }
    // A method call on a typed receiver: dispatch through the receiver's
    // class, declared bases included. An unresolvable receiver stays silent,
    // exactly like an untyped dynamic call.
    if let Some(receiver) = &edge.receiver {
        if let Some(ObjectIdentity::ModuleBinding { scope, name }) =
            receiver.as_object().map(|object| &object.identity)
            && receiver.evidence.ty.is_none()
            && resolve_exact_class(walk.registry, importer, name).is_none()
            && !walk
                .out
                .lifecycle
                .objects
                .contains_key(&ValueOrigin::Module {
                    scope: scope.clone(),
                    name: name.clone(),
                })
            && let Resolution::Targets(targets) =
                walk.linker
                    .resolve_callee(walk.registry, importer, &edge.callee)
        {
            if dispatch_is_exhaustive(&targets) {
                record_resolved_call(walk.registry, importer, edge, walk.out);
            } else {
                record_unresolved_call(walk.registry, importer, edge, walk.out);
            }
            let required = alternatives(walk.out, &targets);
            for (target, function, assurance) in targets {
                enter_function_with_assurance(
                    walk,
                    importer,
                    (target, &function),
                    edge,
                    ReceiverContext::default(),
                    assurance,
                    false,
                );
            }
            walk.out.required = required;
            return;
        }
        follow_dispatch(walk, importer, edge, receiver, lifecycle_registers);
        return;
    }
    // A bare name bound to a local function passed as an argument: follow that
    // function (its effects were not inlined — the caller invoked a parameter).
    if !edge.callee.contains('.')
        && let Some(callback) = callbacks.get(&edge.callee)
    {
        match callback {
            BoundCallable::Function { file, function } => {
                if let Some(target) = walk.registry.files.get(file)
                    && target.function(function).is_some()
                {
                    record_resolved_call(walk.registry, importer, edge, walk.out);
                    enter_function(
                        walk,
                        importer,
                        target,
                        function,
                        edge,
                        ReceiverContext::default(),
                        false,
                    );
                }
            }
            BoundCallable::Class(instance) => {
                let receiver = resolved_object_value(instance);
                follow_dispatch(walk, importer, edge, &receiver, lifecycle_registers);
                for (index, name) in edge.result_bindings() {
                    let mut value = instance.clone();
                    value.origin = edge.origin_for_result(index);
                    if let Some(origin) = &value.origin {
                        walk.out
                            .lifecycle
                            .objects
                            .insert(origin.clone(), value.clone());
                    }
                    walk.env.vars.insert(name.to_string(), value);
                }
            }
            BoundCallable::External { module, member } => {
                if apply_external_resolution(walk, importer, edge, module, member) {
                    record_resolved_call(walk.registry, importer, edge, walk.out);
                } else {
                    record_unresolved_call(walk.registry, importer, edge, walk.out);
                }
            }
        }
        return;
    }
    if !edge.callee.contains('.')
        && let Some(value) = edge
            .arguments
            .iter()
            .find(|argument| argument.name.as_deref() == Some("$callee"))
            .map(|argument| &argument.value)
        && follow_callable_value(walk, importer, edge, value)
    {
        return;
    }
    if !edge.callee.contains('.')
        && let Some(value) = walk.env.values.get(&edge.callee).cloned().or_else(|| {
            (!edge.dynamic_target)
                .then(|| {
                    walk.linker
                        .package_value(walk.registry, importer, &edge.callee)
                })
                .flatten()
        })
        && follow_callable_value(walk, importer, edge, &value)
    {
        return;
    }
    // A statically named class method resolves through the selected linker.
    if let Some((head, member)) = edge.callee.split_once('.')
        && !member.contains('.')
    {
        let receiver = ResolvedObject {
            file: importer.path.clone(),
            class_name: head.to_string(),
            attrs: HashMap::new(),
            values: BTreeMap::new(),
            origin: None,
            ty: None,
        };
        match walk.linker.resolve_method(walk.registry, &receiver, member) {
            Resolution::Targets(targets) => {
                if dispatch_is_exhaustive(&targets) {
                    record_resolved_call(walk.registry, importer, edge, walk.out);
                } else {
                    record_unresolved_call(walk.registry, importer, edge, walk.out);
                }
                let required = alternatives(walk.out, &targets);
                for (target, function, assurance) in targets {
                    let inline_only = target.path == importer.path && edge.effects_propagated;
                    enter_function_with_assurance(
                        walk,
                        importer,
                        (target, &function),
                        edge,
                        ReceiverContext {
                            receiver: Some(receiver.clone()),
                            self_attrs: HashMap::new(),
                        },
                        assurance,
                        inline_only,
                    );
                }
                walk.out.required = required;
                return;
            }
            Resolution::Boundary { reason, detail } => {
                record_unresolved_call(walk.registry, importer, edge, walk.out);
                push_linker_boundary(walk.out, &walk.path, reason, detail);
                return;
            }
            Resolution::External { module, member } => {
                apply_external_resolution(walk, importer, edge, &module, &member);
                record_resolved_call(walk.registry, importer, edge, walk.out);
                return;
            }
            Resolution::Local | Resolution::Unknown => {}
        }
    }
    // A locally bound callee that no bound value resolved is a call through a
    // value this analysis cannot name — never the package symbol it shadows.
    let resolution = if edge.dynamic_target {
        Resolution::Unknown
    } else {
        walk.linker
            .resolve_callee(walk.registry, importer, &edge.callee)
    };
    match resolution {
        Resolution::Targets(targets) => {
            if dispatch_is_exhaustive(&targets) {
                record_resolved_call(walk.registry, importer, edge, walk.out);
            } else {
                record_unresolved_call(walk.registry, importer, edge, walk.out);
            }
            let required = alternatives(walk.out, &targets);
            for (target, function, assurance) in targets {
                enter_function_with_assurance(
                    walk,
                    importer,
                    (target, &function),
                    edge,
                    ReceiverContext::default(),
                    assurance,
                    false,
                );
            }
            walk.out.required = required;
            if let Some(value) = resolve_exact_class(walk.registry, importer, &edge.callee) {
                bind_resolved_constructor(
                    walk.registry,
                    importer,
                    value,
                    edge,
                    &mut walk.env,
                    walk.out,
                );
            }
        }
        Resolution::External { module, member } => {
            if !lifecycle_registers {
                if apply_external_resolution(walk, importer, edge, &module, &member) {
                    record_resolved_call(walk.registry, importer, edge, walk.out);
                } else {
                    record_unresolved_call(walk.registry, importer, edge, walk.out);
                }
            }
            if !lifecycle_registers && !is_constructor_fact(edge) {
                enter_fn_args(walk, importer, edge);
            }
        }
        Resolution::Local => {
            // Same-file callee: a function entered cross-file that calls a
            // same-file sibling still needs that sibling's cross-file calls
            // followed (tox: __main__.py -> run.py:run -> local main ->
            // get_options in another file). Frontends that inline local calls
            // into summaries (Python/Go/Rust) already carry the sibling's
            // effects in the caller's summary, so only the edges are walked;
            // the JS summarizer records call edges without inlining, so a JS
            // sibling's effects are collected here.
            let inline_only = edge.effects_propagated;
            enter_function(
                walk,
                importer,
                importer,
                &edge.callee,
                edge,
                ReceiverContext::default(),
                inline_only,
            );
            if let Some(value) = resolve_exact_class(walk.registry, importer, &edge.callee) {
                bind_resolved_constructor(
                    walk.registry,
                    importer,
                    value,
                    edge,
                    &mut walk.env,
                    walk.out,
                );
            }
        }
        Resolution::Boundary { reason, detail } => {
            record_unresolved_call(walk.registry, importer, edge, walk.out);
            push_linker_boundary(walk.out, &walk.path, reason, detail);
        }
        Resolution::Unknown => {
            record_unresolved_call(walk.registry, importer, edge, walk.out);
            // Unknown calls can invoke callable arguments, and summaries do
            // not necessarily carry the execution plan's unresolved boundary.
            if !lifecycle_registers && !is_constructor_fact(edge) {
                enter_fn_args(walk, importer, edge);
            }
            // The Go frontend records no unresolved_call boundary of its own,
            // so a callable handed to a name no package file declares would
            // otherwise escape silently: the target runs it, and its effects
            // belong to nobody.
            if (edge.dynamic_target
                || walk
                    .linker
                    .callee_is_rebound(walk.registry, importer, &edge.callee))
                && !lifecycle_registers
            {
                push_composed_boundary(
                    walk.out,
                    BoundaryOccurrence {
                        class: effinterp_proto::BoundaryClass::Unresolved,
                        reason: BoundaryReason::DYNAMIC_DISPATCH,
                        detail: format!(
                            "call through binding {:?} whose target is unknown",
                            edge.callee
                        ),
                        source_file: None,
                        callee: None,
                        domains: all_domains(),
                        affected_resource: None,
                        limit: None,
                        path: walk.path.to_vec(),
                        via_dispatch: walk.out.walk_via_dispatch.clone(),
                    },
                );
            } else if walk.linker.callbacks_escape()
                && !lifecycle_registers
                && edge
                    .arguments
                    .iter()
                    .any(|argument| contains_callable(&argument.value))
            {
                push_composed_boundary(
                    walk.out,
                    BoundaryOccurrence {
                        class: effinterp_proto::BoundaryClass::Unresolved,
                        reason: BoundaryReason::new("escaped_callable"),
                        detail: format!(
                            "callable passed to unresolved call target {:?}",
                            edge.callee
                        ),
                        source_file: None,
                        callee: None,
                        domains: all_domains(),
                        affected_resource: None,
                        limit: None,
                        path: walk.path.to_vec(),
                        via_dispatch: walk.out.walk_via_dispatch.clone(),
                    },
                );
            } else if walk.linker.unresolved_call_is_boundary()
                && !lifecycle_registers
                && !is_constructor_fact(edge)
            {
                push_linker_boundary(
                    walk.out,
                    &walk.path,
                    BoundaryReason::UNRESOLVED_CALL,
                    format!("call target {:?} is unresolved", edge.callee),
                );
            }
        }
    }
}

fn push_linker_boundary(
    out: &mut Composition,
    path: &[String],
    reason: BoundaryReason,
    detail: String,
) {
    push_composed_boundary(
        out,
        BoundaryOccurrence {
            class: effinterp_proto::BoundaryClass::Unresolved,
            reason,
            detail,
            source_file: None,
            callee: None,
            domains: all_domains(),
            affected_resource: None,
            limit: None,
            path: path.to_vec(),
            via_dispatch: out.walk_via_dispatch.clone(),
        },
    );
}

/// Resolved alternatives: none of several targets is proven to run. Returns
/// the flag to restore after entering them.
fn alternatives<T>(out: &mut Composition, targets: &[T]) -> bool {
    let required = out.required;
    out.required &= targets.len() == 1;
    required
}

fn dispatch_is_exhaustive(targets: &[(&ModuleFile, String, Assurance)]) -> bool {
    !targets.is_empty()
        && targets
            .iter()
            .all(|(_, _, assurance)| *assurance != Assurance::Heuristic)
}

fn record_resolved_call(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
    out: &mut Composition,
) {
    let Some(resolved) = frontend_call_reference(registry, importer, edge) else {
        return;
    };
    if !out.resolved_calls.contains(&resolved) {
        out.resolved_calls.push(resolved);
    }
}

fn record_resolved_dispatch_call(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
    instance: &ResolvedObject,
    method: &str,
    out: &mut Composition,
) {
    if frontend_call_reference(registry, importer, edge).is_some() {
        record_resolved_call(registry, importer, edge, out);
        return;
    }
    let Some(callee) = registry
        .linker(importer.lang)
        .import_dispatch_reference(registry, importer, edge, instance, method)
    else {
        return;
    };
    let resolved = ResolvedCall {
        source_file: importer.path.clone(),
        callee,
    };
    if !out.resolved_calls.contains(&resolved) {
        out.resolved_calls.push(resolved);
    }
}

fn record_unresolved_call(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
    out: &mut Composition,
) {
    let Some(unresolved) = frontend_call_reference(registry, importer, edge) else {
        return;
    };
    if !out.unresolved_calls.contains(&unresolved) {
        out.unresolved_calls.push(unresolved);
    }
}

fn bind_external_necessity(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    effect: &mut Effect,
) {
    if !walk.out.required {
        return;
    }
    let Some(function) = edge_origin_function(edge).and_then(|name| importer.function(name)) else {
        return;
    };
    let Some(site) = &edge.call_site else {
        return;
    };
    let Some(call) = function
        .calls
        .iter()
        .position(|candidate| candidate.call_site.as_ref() == Some(site))
    else {
        return;
    };
    // Use the frontend's occurrence-to-call mapping, not the external
    // model's existence or its resource precision, as reachability evidence.
    for (slot, at) in function.summary.control_flow.effects_at_calls() {
        if !charge_compose_step(walk.out, &walk.path) {
            return;
        }
        if at != call as u32 {
            continue;
        }
        let Some(proven) = function.summary.effects.get(slot as usize) else {
            continue;
        };
        if proven.operation == effect.operation
            && proven.resource == effect.resource
            && proven.attributes == effect.attributes
            && proven.realm == effect.realm
        {
            effect.modality = Modality::MustOnSuccess;
            return;
        }
    }
}

fn apply_external_resolution(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    module: &str,
    member: &str,
) -> bool {
    let linker = walk.registry.linker(importer.lang);
    if let Some(effects) =
        linker.semantic_external_effects(module, member, &edge.positional_values())
    {
        for mut effect in effects {
            bind_external_necessity(walk, importer, edge, &mut effect);
            if !reserve_effect(walk.out, &walk.path) {
                break;
            }
            if let Some(slot) = walk.out.occurrence_effects.iter().position(|occurrence| {
                let existing = &walk.out.effects[occurrence.effect];
                occurrence.source_file == importer.path
                    && occurrence.path == walk.path
                    && existing.effect.operation == effect.operation
                    && existing.effect.request_assurance == effect.request_assurance
                    && match (&existing.effect.resource, &effect.resource) {
                        (ResourceExpr::Unresolved { .. }, _) => true,
                        (
                            ResourceExpr::Concrete {
                                identity:
                                    effinterp_proto::ResourceIdentity::Process {
                                        executable: existing,
                                        ..
                                    },
                            },
                            ResourceExpr::Concrete {
                                identity:
                                    effinterp_proto::ResourceIdentity::Process {
                                        executable: resolved,
                                        ..
                                    },
                            },
                        ) => existing == resolved,
                        _ => existing.effect.resource == effect.resource,
                    }
            }) {
                remove_composed_occurrence(walk.out, slot);
            }
            push_composed_effect(
                walk.out,
                EffectOccurrence {
                    effect,
                    source_file: importer.path.clone(),
                    path: walk.path.to_vec(),
                    assurance: walk.out.walk_assurance,
                    via_dispatch: walk.out.walk_via_dispatch.clone(),
                },
            );
        }
        return true;
    }
    let arguments = edge.resource_arguments();
    if let Some(effects) = linker.external_effects(module, member, &arguments) {
        for mut effect in effects {
            if !reserve_effect(walk.out, &walk.path) {
                break;
            }
            bind_external_necessity(walk, importer, edge, &mut effect);
            let subprocess = effect.operation.0 == "process.exec";
            let subprocess_resource = subprocess.then(|| effect.resource.clone());
            push_composed_effect(
                walk.out,
                EffectOccurrence {
                    effect,
                    source_file: importer.path.clone(),
                    path: walk.path.to_vec(),
                    assurance: walk.out.walk_assurance,
                    via_dispatch: walk.out.walk_via_dispatch.clone(),
                },
            );
            if subprocess {
                push_composed_boundary(
                    walk.out,
                    BoundaryOccurrence {
                        class: effinterp_proto::BoundaryClass::Unresolved,
                        reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
                        detail: format!("{module}.{member} spawns a subprocess"),
                        source_file: None,
                        callee: None,
                        domains: linker.subprocess_boundary_domains(),
                        affected_resource: subprocess_resource,
                        limit: None,
                        path: walk.path.to_vec(),
                        via_dispatch: walk.out.walk_via_dispatch.clone(),
                    },
                );
            }
        }
        return true;
    }
    let cross_module_detail = if member.contains('.') {
        format!("import target {module:?} is not an analyzed repo file for {module}.{member}")
    } else {
        format!("import target {module:?} is not an analyzed repo file")
    };
    let classification =
        if edge.external_inert.as_deref() == Some(format!("{module}.{member}").as_str()) {
            Some(ExternalCall::Inert)
        } else {
            linker.classify_external(walk.registry, module, member, Some(arguments.len()))
        };
    let (class, reason, detail, domains) = match classification {
        Some(ExternalCall::Modeled) => (
            effinterp_proto::BoundaryClass::Unmodeled,
            BoundaryReason::EXTERNAL_MODELED,
            format!("{module}.{member} is covered by an effect model"),
            Vec::new(),
        ),
        Some(ExternalCall::Inert) => (
            effinterp_proto::BoundaryClass::Unmodeled,
            BoundaryReason::EXTERNAL_INERT,
            format!("{module}.{member} is a known effect-free external call"),
            Vec::new(),
        ),
        // Exact evidence bounds an unmodeled external call to the domains
        // its module can reach; an unrecognized target stays broad.
        Some(ExternalCall::Unmodeled(domains)) => (
            effinterp_proto::BoundaryClass::Unmodeled,
            BoundaryReason::EXTERNAL_UNMODELED,
            format!("{module}.{member} is an unmodeled external call"),
            owned_domains(domains),
        ),
        None if walk.registry.linker(importer.lang).callbacks_escape()
            && edge
                .arguments
                .iter()
                .any(|argument| contains_callable(&argument.value)) =>
        {
            (
                effinterp_proto::BoundaryClass::Unresolved,
                BoundaryReason::new("escaped_callable"),
                format!("callable passed to unresolved import target {module:?}"),
                all_domains(),
            )
        }
        None => (
            effinterp_proto::BoundaryClass::Unresolved,
            BoundaryReason::CROSS_MODULE,
            cross_module_detail,
            all_domains(),
        ),
    };
    let resolved = domains.is_empty();
    push_composed_boundary(
        walk.out,
        BoundaryOccurrence {
            class,
            reason,
            detail,
            source_file: None,
            callee: None,
            domains,
            affected_resource: None,
            limit: None,
            path: walk.path.to_vec(),
            via_dispatch: walk.out.walk_via_dispatch.clone(),
        },
    );
    resolved
}

/// Dispatch a method call through its typed receiver: resolve the receiver's
/// class, look the method up through inheritance, and enter it with the
/// instance context. A method on the receiver's own file is entered
/// edges-only (its effects are already inlined into the caller's summary).
/// Only a single structurally resolved constant receiver preserves the
/// caller's necessity; runtime-selected receivers remain optional.
fn follow_dispatch(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    receiver: &SemanticValue,
    lifecycle_registers: bool,
) -> bool {
    let proven = module_receiver_targets(walk.registry, importer, edge);
    let required = walk.out.required;
    let target = proven.as_deref().and_then(|targets| match targets {
        [(file, name, Assurance::Exact)] if required => Some((file.path.as_str(), name.as_str())),
        _ => None,
    });
    walk.out.required = false;
    let handled =
        follow_receiver_dispatch(walk, importer, edge, receiver, lifecycle_registers, target);
    walk.out.required = required;
    handled
}

fn module_receiver_targets<'a>(
    registry: &'a ModuleRegistry,
    file: &'a ModuleFile,
    edge: &CallEdge,
) -> Option<Vec<(&'a ModuleFile, String, Assurance)>> {
    if edge.dynamic_target
        || registry
            .linker(file.lang)
            .callee_is_rebound(registry, file, &edge.callee)
    {
        return None;
    }
    let ObjectIdentity::ModuleBinding { name, .. } = edge.receiver_identity()? else {
        return None;
    };
    let linker = registry.linker(file.lang);
    let candidates = linker.class_candidates(registry, file, name);
    let [(instance, Assurance::Exact)] = candidates.as_slice() else {
        return None;
    };
    let (_, method) = edge.callee.rsplit_once('.')?;
    match linker.resolve_method(registry, instance, method) {
        Resolution::Targets(targets)
            if !targets.is_empty()
                && targets
                    .iter()
                    .all(|(_, _, assurance)| *assurance == Assurance::Exact) =>
        {
            Some(targets)
        }
        _ => None,
    }
}

fn follow_receiver_dispatch(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    receiver: &SemanticValue,
    lifecycle_registers: bool,
    required_target: Option<(&str, &str)>,
) -> bool {
    if let Some(value) = edge
        .arguments
        .iter()
        .find(|argument| argument.name.as_deref() == Some("$callee"))
        .map(|argument| &argument.value)
        && follow_callable_value(walk, importer, edge, value)
    {
        return true;
    }
    let mut insts: Vec<ResolvedObject> = match receiver.as_object().map(|object| &object.identity) {
        Some(ObjectIdentity::Class { name, .. }) => {
            let mut candidates: Vec<ResolvedObject> =
                resolve_instance(walk.registry, importer, &walk.env, receiver, 0)
                    .into_iter()
                    .collect();
            if candidates.is_empty()
                && let Some(v) = edge
                    .callee
                    .split('.')
                    .next()
                    .and_then(|v| walk.env.vars.get(v).cloned())
            {
                candidates.push(v);
            }
            if candidates.is_empty() {
                candidates.push(ResolvedObject {
                    file: importer.path.clone(),
                    class_name: name.clone(),
                    attrs: HashMap::new(),
                    values: BTreeMap::new(),
                    origin: None,
                    ty: receiver.evidence.ty.clone(),
                });
            }
            candidates
        }
        _ => resolve_instance(walk.registry, importer, &walk.env, receiver, 0)
            .into_iter()
            .collect(),
    };
    for instance in &mut insts {
        if let Some(origin) = &instance.origin
            && let Some(carried) = walk.out.lifecycle.objects.get(origin)
        {
            *instance = carried.clone();
        }
    }
    if insts.is_empty() {
        let class_name = match &receiver.evidence.ty {
            Some(TypeRef::Repo { name, .. }) => name.clone(),
            Some(TypeRef::External { path }) => path.clone(),
            None => String::new(),
        };
        insts.push(ResolvedObject {
            file: importer.path.clone(),
            class_name,
            attrs: HashMap::new(),
            values: BTreeMap::new(),
            origin: None,
            ty: receiver.evidence.ty.clone(),
        });
    }
    let method = match edge.callee.rsplit_once('.') {
        Some((_, m)) => m.to_string(),
        None => "__init__".to_string(),
    };
    for inst in &insts {
        if let Some(value) = inst.values.get(&method)
            && follow_callable_value(walk, importer, edge, value)
        {
            return true;
        }
        if let Some(TypeRef::External {
            path: receiver_type,
        }) = &inst.ty
            && let Some(effects) = python_external_method_effects(
                receiver_type,
                &method,
                inst.values
                    .get("__resource__")
                    .map(SemanticValue::lower_resource),
                &edge.arguments,
            )
        {
            for mut effect in effects {
                effect.resource =
                    normalize_resource(cap_depth(effect.resource), PathPlatform::Posix);
                push_composed_effect(
                    walk.out,
                    EffectOccurrence {
                        effect,
                        source_file: importer.path.clone(),
                        path: walk.path.to_vec(),
                        assurance: walk.out.walk_assurance,
                        via_dispatch: walk.out.walk_via_dispatch.clone(),
                    },
                );
            }
            record_resolved_call(walk.registry, importer, edge, walk.out);
            return true;
        }
        let resolution =
            walk.registry
                .linker(importer.lang)
                .resolve_method(walk.registry, inst, &method);
        match resolution {
            Resolution::Targets(targets) => {
                // Necessity must refer to the target actually entered, not a
                // different resolution of the same receiver expression.
                walk.out.required = required_target.is_some_and(|(path, name)| {
                    matches!(targets.as_slice(), [(file, method, Assurance::Exact)] if file.path == path && method == name)
                });
                if dispatch_is_exhaustive(&targets) {
                    record_resolved_dispatch_call(
                        walk.registry,
                        importer,
                        edge,
                        inst,
                        &method,
                        walk.out,
                    );
                } else {
                    record_unresolved_call(walk.registry, importer, edge, walk.out);
                }
                enter_dispatch_targets(walk, importer, edge, receiver, inst, &method, targets);
                return true;
            }
            Resolution::Boundary { reason, detail } => {
                record_unresolved_call(walk.registry, importer, edge, walk.out);
                push_linker_boundary(walk.out, &walk.path, reason, detail);
                return true;
            }
            Resolution::External { module, member } => {
                if lifecycle_match(
                    walk.registry,
                    importer,
                    edge,
                    Some(inst),
                    &walk.out.lifecycle,
                )
                .is_none()
                {
                    apply_external_resolution(walk, importer, edge, &module, &member);
                    record_resolved_call(walk.registry, importer, edge, walk.out);
                    if !lifecycle_registers {
                        enter_fn_args(walk, importer, edge);
                    }
                    return true;
                }
            }
            Resolution::Local | Resolution::Unknown => {}
        }
        let Some(matched) = lifecycle_match(
            walk.registry,
            importer,
            edge,
            Some(inst),
            &walk.out.lifecycle,
        ) else {
            continue;
        };
        if matched.sig.role != SigRole::Dispatches || inst.origin.is_none() {
            continue;
        }
        for hook in matched.sig.hooks {
            match walk
                .registry
                .linker(importer.lang)
                .resolve_method(walk.registry, inst, hook)
            {
                Resolution::Targets(mut targets) => {
                    for target in &mut targets {
                        target.2 = target.2.max(matched.assurance);
                    }
                    if dispatch_is_exhaustive(&targets) {
                        record_resolved_dispatch_call(
                            walk.registry,
                            importer,
                            edge,
                            inst,
                            hook,
                            walk.out,
                        );
                    } else {
                        record_unresolved_call(walk.registry, importer, edge, walk.out);
                    }
                    let previous_via = walk.out.walk_via_dispatch.replace(DispatchVia {
                        model: matched.model.id.to_string(),
                        registration_path: walk.path.to_vec(),
                        dispatch_path: walk.path.to_vec(),
                    });
                    enter_dispatch_targets(walk, importer, edge, receiver, inst, hook, targets);
                    walk.out.walk_via_dispatch = previous_via;
                    return true;
                }
                Resolution::Boundary { reason, detail } => {
                    record_unresolved_call(walk.registry, importer, edge, walk.out);
                    push_linker_boundary(walk.out, &walk.path, reason, detail);
                    return true;
                }
                Resolution::Local | Resolution::External { .. } | Resolution::Unknown => {}
            }
        }
    }
    let mut handled = false;
    if method != "__init__" {
        record_unresolved_call(walk.registry, importer, edge, walk.out);
        let exact_repository_receivers = insts.iter().all(|inst| {
            let exact_class = walk
                .registry
                .files
                .get(&inst.file)
                .and_then(|file| class_entry(file, &inst.class_name))
                .is_some();
            exact_class
                && match &inst.ty {
                    Some(TypeRef::External { path }) => {
                        canonical_rust_std_type(path).is_none()
                            && path.rsplit("::").next() == Some(inst.class_name.as_str())
                    }
                    _ => true,
                }
        });
        let detail = walk
            .registry
            .linker(importer.lang)
            .unresolved_method_detail(&insts, &method, edge, exact_repository_receivers);
        if let Some(detail) = detail {
            handled = true;
            push_composed_boundary(
                walk.out,
                BoundaryOccurrence {
                    class: effinterp_proto::BoundaryClass::Unresolved,
                    reason: BoundaryReason::UNRESOLVED_CALL,
                    detail,
                    source_file: None,
                    callee: None,
                    domains: all_domains(),
                    affected_resource: None,
                    limit: None,
                    path: walk.path.to_vec(),
                    via_dispatch: walk.out.walk_via_dispatch.clone(),
                },
            );
        }
    }
    if !lifecycle_registers {
        enter_fn_args(walk, importer, edge);
    }
    handled
}

fn enter_dispatch_targets(
    walk: &mut CompositionWalk<'_>,
    importer: &ModuleFile,
    edge: &CallEdge,
    receiver_value: &SemanticValue,
    inst: &ResolvedObject,
    method: &str,
    targets: Vec<(&ModuleFile, String, Assurance)>,
) {
    let self_attrs = match receiver_value.as_object().map(|object| &object.identity) {
        // The same instance as the caller's receiver: its attrs carry over.
        Some(ObjectIdentity::Receiver) => walk.env.self_attrs.clone(),
        // A constructor-typed receiver: `resolve_instance` already typed its
        // attrs from the constructor's instance-typed arguments.
        Some(ObjectIdentity::Class { .. }) => inst.attrs.clone(),
        // Construction (`cls(...)`) or unknown provenance: only attributes
        // `__init__` constructs directly are known — plus, for a constructor,
        // the parameters this very call binds.
        _ if method == "__init__" => {
            let resolved = resolve_obj_args(walk.registry, importer, &walk.env, &edge.arguments, 0);
            instance_attrs(walk.registry, inst, &resolved)
        }
        // A parameter/variable/attribute-carried instance keeps the attrs its
        // construction established; fall back to the directly-constructed ones.
        _ if !inst.attrs.is_empty() => inst.attrs.clone(),
        _ => instance_attrs(walk.registry, inst, &[]),
    };
    // The frontend inlines a same-file method call into the caller's summary
    // only when it can name the callee statically (`self.m()`, `Cls.m()`).
    // A constructor-chained `Class().method()`, a `cls(...)` constructor, a
    // typed local (`x = Class(); x.m()`), and a deeper receiver chain
    // (`self.attr.m()`) are NOT inlined, so their effects must be collected
    // here even within one file. The Go and Rust frontends never resolve
    // method calls in-file, so their methods are always entered fully.
    let statically_inlined = match (edge.receiver_identity(), edge.callee.rsplit_once('.')) {
        (Some(ObjectIdentity::Class { .. }), _) => false,
        (_, Some((head, _))) => !head.contains('.'),
        _ => false,
    };
    let previous_exhaustive = walk.out.recursive_dispatch_exhaustive;
    walk.out.recursive_dispatch_exhaustive &= dispatch_is_exhaustive(&targets);
    for (target, function, assurance) in targets {
        let mut receiver = inst.clone();
        let qualified_identity = walk
            .registry
            .linker(target.lang)
            .qualified_class_dispatch(&inst.class_name);
        if !qualified_identity
            && walk
                .registry
                .files
                .get(&receiver.file)
                .and_then(|file| class_entry(file, &receiver.class_name))
                .is_none()
        {
            receiver.file = target.path.clone();
            receiver.class_name = function
                .split_once('.')
                .map(|(class, _)| class)
                .unwrap_or(&function)
                .to_string();
        }
        let inline_only =
            target.path == importer.path && edge.effects_propagated && statically_inlined;
        enter_function_with_assurance(
            walk,
            importer,
            (target, &function),
            edge,
            ReceiverContext {
                receiver: Some(receiver),
                self_attrs: self_attrs.clone(),
            },
            assurance,
            inline_only,
        );
    }
    walk.out.recursive_dispatch_exhaustive = previous_exhaustive;
}

/// A binding for `local` in a module: eager (import-time) bindings first, then
/// scoped ones (function-local imports) — a name bound at module scope wins.
fn find_import<'a>(
    summary: &'a effinterp_engine::ModuleSummary,
    local: &str,
) -> Option<&'a ImportBinding> {
    summary
        .imports
        .iter()
        .chain(&summary.scoped_imports)
        .find(|i| i.local == local)
}

fn frontend_call_reference(
    registry: &ModuleRegistry,
    importer: &ModuleFile,
    edge: &CallEdge,
) -> Option<ResolvedCall> {
    Some(ResolvedCall {
        source_file: importer.path.clone(),
        callee: registry
            .linker(importer.lang)
            .import_call_reference(importer, edge)?,
    })
}

#[cfg(test)]
mod tests;
