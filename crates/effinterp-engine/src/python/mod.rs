//! Effect-directed Python frontend.
//!
//! Parses Python source with `rustpython-parser` (v0.4; the newer `ruff`
//! parser requires a toolchain past this workspace's pin) and walks the AST
//! for calls into known effect APIs — `open`, `os`, `shutil`, `pathlib`,
//! `subprocess`, `requests`/`urllib`. It does not interpret Python; it follows
//! only what reaches an effect boundary, keeps non-literal arguments symbolic,
//! and records an explicit boundary for anything dynamic (`eval`, `exec`,
//! `getattr`, `__import__`).
//!
//! The statement and expression walks dispatch into the modules below. The
//! entry point seeds one shared walker for each source and owns its limits.

mod argv;
mod ast_expressions;
mod branch_join;
mod call_resolution;
mod context_managers;
mod control;
mod data_file_values;
mod dataflow_capture;
mod decoders;
mod decorators;
mod deferred_calls;
mod definitions;
mod effect_emission;
mod expression_walk;
mod file_handles;
mod fs_path_lowering;
mod host_environment;
mod import_bindings;
mod imports;
mod instance_tracking;
pub(crate) mod ipython;
mod literal_values;
mod loop_values;
mod memory_tar;
mod model;
mod name_bindings;
mod package_search;
mod path_values;
mod printed_environment;
mod pytest_collection;
mod registration;
mod resolve;
mod returns;
mod runtime;
mod statement_walk;
mod static_containers;
mod subprocess_launch;
mod summary;
mod summary_application;
mod summary_capture;
mod text_flow;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ProvenanceKind, ProvenanceRef, ResourceExpr,
};
use rustpython_parser::ast;
use rustpython_parser::{Parse, text_size::TextRange};

use crate::builder::PlanBuilder;
use crate::control_flow::{Requirements, SiteFacts};
use crate::flow::StageWriter;
use crate::lang::frontend::{Frontend, FrontendInput, ParseFailure, ParseOutcome, WalkOutcome};
use crate::module_summary::ClassEntry;
use crate::nest::Nest;
use crate::summary::Summary;
use crate::{ScopeKey, SemanticValue, ValueArgument, ValueOrigin};

use definitions::{PythonFunctionDef, PythonInitAttrValue};
use definitions::{
    collect_class_bases, collect_class_sets, collect_class_strings, collect_classes, collect_defs,
    collect_path_attrs,
};
use import_bindings::partition_python_module_execution;
use model::{Receiver, ReceiverKind};
use name_bindings::rebound_body_names;
use registration::python_framework_roots;
use resolve::PythonImportNames;
use returns::{CallReturn, ReturnSite};
use static_containers::StaticContainer;
use subprocess_launch::{CapturedSpawn, source_changes_cwd};
use summary_capture::{ArgumentConsumers, ConstantElements, PythonSummaryCapture, SummaryWrite};

pub use fs_path_lowering::python_plugin_path_pattern;
pub(crate) use imports::{PytestMode, PythonImportCache, PythonImportSearch};
pub(crate) use package_search::{PackageDirs, package_dirs};
pub(crate) use runtime::runtime_imports;

/// Effect domains this frontend can surface. Calls the walker cannot classify
/// downgrade their reachable domains at the call site.
const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

/// Cap on effects retained in one function summary, so a pathological function
/// (or an unconverged recursive one) cannot make a summary grow without bound.
/// Each retained effect is also charged to the shared analysis byte budget.
/// A summary that reaches the cap records a `max_summary_effects` limit
/// boundary for what it leaves out.
const MAX_SUMMARY_EFFECTS: usize = 1024;
const MAX_SUMMARY_BOUNDARIES: usize = 128;

/// Cap on call edges retained per function, to bound extraction output.
const MAX_CALL_EDGES: usize = 128;

/// Effects of methods on instances whose constructor has an exact external
/// Python type. The receiver resource is supplied separately from arguments.
pub fn python_external_method_effects(
    receiver_type: &str,
    method: &str,
    receiver_resource: Option<ResourceExpr>,
    args: &[ValueArgument],
) -> Option<Vec<Effect>> {
    model::external_method_effects(receiver_type, method, receiver_resource, args)
}

pub(crate) fn registrations(
    source: &str,
    file: &str,
    max_bytes: u64,
) -> Result<Vec<crate::Registration>, &'static str> {
    let suite = ast::Suite::parse(source, file).map_err(|_| "parse_error: registration scan")?;
    registration::fastapi_registrations(&suite, file, max_bytes)
}

pub(crate) struct PythonFrontend {
    ipython: Option<ipython::CellActions>,
}

#[allow(non_upper_case_globals)]
pub(crate) const PythonFrontend: PythonFrontend = PythonFrontend { ipython: None };

impl PythonFrontend {
    fn ipython(actions: ipython::CellActions) -> Self {
        Self {
            ipython: Some(actions),
        }
    }
}

impl Frontend for PythonFrontend {
    const LANGUAGE: &'static str = "python";
    const DOMAINS: &'static [&'static str] = &DOMAINS;
    type Ast<'a> = ast::Suite;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        match ast::Suite::parse(source, "<python>") {
            Ok(ast) => ParseOutcome {
                ast: Some(ast),
                failure: None,
            },
            Err(err) => ParseOutcome {
                ast: None,
                failure: Some(ParseFailure {
                    detail: err.to_string(),
                }),
            },
        }
    }
    fn parse_failure(
        &self,
        builder: &mut PlanBuilder,
        scope: Option<ProvenanceRef>,
        failure: &ParseFailure,
    ) {
        python_boundary(
            builder,
            scope,
            BoundaryReason::PARSE_ERROR,
            BoundaryClass::ParseFailure,
            None,
            Some(failure.detail.clone()),
        );
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        suite: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let source = input.source;
        let cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        // Imported modules use the same import-time statement partition as
        // summaries. Keep the original source bytes and ranges for provenance.
        let selected_registration = nest.registration.is_some() && builder.execution_depth() == 1;
        let import_stmts;
        let suite = if builder.current_execution_is_dependency() || selected_registration {
            import_stmts = partition_python_module_execution(suite).0;
            &import_stmts
        } else {
            suite
        };
        for domain in DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        if depth == 0 {
            python_boundary(
                builder,
                scope,
                BoundaryReason::FRONTEND_PARTIAL,
                BoundaryClass::Unmodeled,
                None,
                Some("python frontend models selected effect APIs".to_string()),
            );
        }

        // Collect module-level function definitions. A defined-but-never-called
        // function is summarized but contributes effects only where a call to it
        // is actually reached during execution.
        let (mut walker, classes) = PythonWalker::for_execution(
            builder,
            nest,
            source,
            cwd,
            cwd_node,
            scope,
            depth,
            suite,
            self.ipython.clone(),
        );
        let declared_callables: Vec<String> = walker
            .defs
            .iter()
            .filter(|def| def.parent.is_none() && (def.owner.is_none() || def.name.contains('.')))
            .map(|def| def.name.clone())
            .collect();
        let first_effect = walker.builder.effects_len();
        walker.import_search = nest.python_import_search.borrow_mut().take().or_else(|| {
            (walker.builder.execution_depth() == 1)
                .then(|| imports::root_import_search(nest))
                .flatten()
        });
        // Seed imports and module constants before execution. Calls infer their
        // own summaries, so uncalled declarations cannot starve an execution root.
        walker.seed_import_bindings(suite);
        control::collect_bound(suite, &mut walker.module_binds);
        walker.module_names = rebound_body_names(suite, false);
        walker.module_names.extend(rebound_body_names(suite, true));
        walker.collect_consts(suite);
        walker.var_scope = walker.consts.clone();
        walker.concatenated_vars = walker.const_concatenations.clone();
        walker.unbounded_string_vars = walker.const_unbounded_strings.clone();
        let (framework_roots, framework_decorators, registration_limit) = python_framework_roots(
            suite,
            &walker.defs,
            &classes,
            &walker.imports,
            nest.limits.max_analysis_bytes,
        );
        if let Some(limit) = registration_limit {
            walker.builder.note_saturated_at(limit, None);
        }
        walker.framework_decorators = framework_decorators;
        walker.builder.control_enter(source, false, |graph| {
            control::build(
                graph,
                suite,
                control::Entry::Main,
                &std::collections::HashSet::new(),
            )
        });
        walker.walk_body(suite);
        walker.builder.control_leave();
        if !walker.builder.current_execution_is_dependency() {
            walker.record_printed_data_key(suite);
        }
        for root in framework_roots
            .into_iter()
            .filter(|_| !selected_registration)
        {
            walker.apply_local_root(&root);
        }
        walker.apply_pytest_collected(suite);
        walker.stage_writer.commit(walker.builder);
        let entered_callables = walker.entered_callables;
        let free_resource_parameter = walker.free_resource_parameter.get();
        drop(walker);
        if free_resource_parameter {
            python_boundary(
                builder,
                scope,
                BoundaryReason::FRONTEND_PARTIAL,
                BoundaryClass::Unmodeled,
                None,
                Some("effect resource depends on an unbound Python name".to_string()),
            );
        }
        WalkOutcome {
            declared_callables: if !declared_callables.is_empty()
                && !entered_callables
                && builder.effects_len() == first_effect
            {
                declared_callables
            } else {
                Vec::new()
            },
        }
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summary::summarize_ast(source, ast, file, scope)
    }
}

impl<'a, 'b> PythonWalker<'a, 'b> {
    /// An execution-mode walker over one parsed module, before imports,
    /// constants, or import search are seeded.
    #[allow(clippy::too_many_arguments)]
    fn for_execution(
        builder: &'b mut PlanBuilder,
        nest: &'a Nest<'a>,
        source: &'a str,
        cwd: Option<&'a str>,
        cwd_node: Option<ProvenanceRef>,
        scope: Option<ProvenanceRef>,
        depth: u64,
        suite: &ast::Suite,
        ipython: Option<ipython::CellActions>,
    ) -> (Self, Vec<ClassEntry>) {
        let max_nodes = nest.limits.max_python_nodes;
        let registration_spans =
            match registration::fastapi_registrations(suite, "", nest.limits.max_analysis_bytes) {
                Ok(registrations) => registrations
                    .into_iter()
                    .flat_map(|registration| registration.spans)
                    .collect(),
                Err(limit) => {
                    builder.note_saturated_at(limit, None);
                    HashSet::new()
                }
            };
        let mut defs: Vec<PythonFunctionDef> = Vec::new();
        collect_defs(suite, &mut defs);
        let (classes, attr_values) = collect_classes(suite);
        let walker = PythonWalker {
            builder,
            nest,
            source,
            condition_source: effinterp_proto::ConditionSource::new(source),
            cwd: cwd.map(str::to_string),
            cwd_node,
            chdir: None,
            scope,
            depth,
            imports: PythonImportNames::default(),
            defs,
            summaries: std::collections::HashMap::new(),
            demand_summaries: true,
            summary_in_progress: HashSet::new(),
            summary_cycles: HashSet::new(),
            summary_refining: false,
            summary_spans: std::collections::HashMap::new(),
            summary_effect_sources: HashMap::new(),
            decorated_summaries: std::collections::HashMap::new(),
            spawn_summaries: std::collections::HashMap::new(),
            consts: std::collections::HashMap::new(),
            shared_vars: HashSet::new(),
            const_concatenations: HashSet::new(),
            const_unbounded_strings: HashSet::new(),
            var_scope: std::collections::HashMap::new(),
            path_vars: HashSet::new(),
            branch_mixed_path_vars: HashSet::new(),
            concatenated_vars: HashSet::new(),
            unbounded_string_vars: HashSet::new(),
            collections: std::collections::HashMap::new(),
            widened_vars: HashSet::new(),
            sessions: std::collections::HashMap::new(),
            modeled_values: std::collections::HashMap::new(),
            literal_bytes: RefCell::new(std::collections::HashMap::new()),
            open_writes: std::collections::HashMap::new(),
            write_handles: std::collections::HashMap::new(),
            return_receivers: std::collections::HashMap::new(),
            connected_sockets: std::collections::HashMap::new(),
            stdin_connection: None,
            zero_loop_calls: std::collections::HashMap::new(),
            return_instances: std::collections::HashMap::new(),
            summary_instances: std::collections::HashMap::new(),
            instance_sequences: std::collections::HashMap::new(),
            capture: None,
            capture_condition_depth: 0,
            entered_callables: false,
            framework_decorators: HashSet::new(),
            registration_spans,
            reported_unresolved: HashSet::new(),
            nodes_left: max_nodes,
            node_budget_hit: false,
            free_resource_parameter: Cell::new(false),
            walk_depth: 0,
            flow_vars: std::collections::HashMap::new(),
            stage_writer: StageWriter::default(),
            current_params: Vec::new(),
            current_function: None,
            current_path_params: HashSet::new(),
            current_class: None,
            class_names: classes.iter().map(|c| c.name.clone()).collect(),
            class_bases: collect_class_bases(&classes),
            path_attrs: collect_path_attrs(&classes),
            attr_values,
            class_strings: collect_class_strings(suite),
            class_sets: collect_class_sets(suite),
            class_set_vars: std::collections::HashMap::new(),
            instance_vars: std::collections::HashMap::new(),
            instance_attr_rebindings: std::collections::HashMap::new(),
            bound_vars: HashSet::new(),
            receiver_rebindings: HashSet::new(),
            pending_binds: None,
            discarded_call: None,
            source_changes_cwd: source_changes_cwd(source, ipython.as_ref()),
            eager_call: None,
            synchronous_call: None,
            deferred_containers: std::collections::HashMap::new(),
            deferred_vars: std::collections::HashMap::new(),
            pending_deferred_container: None,
            fact_file: String::new(),
            fact_scope: None,
            fact_function: String::new(),
            site_ordinal: Cell::new(0),
            site_origins: RefCell::new(std::collections::HashMap::new()),
            module_capture: false,
            execute_deferred: false,
            deferred_call: None,
            import_search: None,
            imported_summaries: std::collections::HashMap::new(),
            control_applications: Vec::new(),
            summary_requirements: std::collections::HashMap::new(),
            summary_stdout: std::collections::HashMap::new(),
            summary_flows: std::collections::HashMap::new(),
            summary_param_flows: std::collections::HashMap::new(),
            applied_param_flows: Vec::new(),
            argument_consumers: None,
            summary_writes: std::collections::HashMap::new(),
            applied_writes: Vec::new(),
            pending_writes: None,
            flow_elements: std::collections::HashMap::new(),
            summary_returns: std::collections::HashMap::new(),
            call_returns: std::collections::HashMap::new(),
            module_binds: HashSet::new(),
            module_names: HashSet::new(),
            environment_stages: std::collections::HashMap::new(),
            environment_holds: std::collections::HashMap::new(),
            environment_given: printed_environment::EnvironmentShape::Mapping,
            summary_environment: std::collections::HashMap::new(),
            default_values: std::collections::HashMap::new(),
            class_outer: Vec::new(),
            local_calls_applied: 0,
            environment_rewritten: false,
            written_environment: BTreeSet::new(),
            ipython: ipython.map(|cell| ipython::IpythonState {
                actions: cell.actions,
                bindings: Default::default(),
                environment: Default::default(),
                environment_nodes: Default::default(),
                get_ipython_owned: true,
            }),
        };
        (walker, classes)
    }
}

struct PythonWalker<'a, 'b> {
    builder: &'b mut PlanBuilder,
    nest: &'a Nest<'a>,
    source: &'a str,
    condition_source: effinterp_proto::ConditionSource,
    cwd: Option<String>,
    cwd_node: Option<ProvenanceRef>,
    /// The directory the program last moved to with `os.chdir`, which later
    /// children start in instead of the launch cwd; unresolved when the
    /// target, or the branch that ran it, is unknown.
    chdir: Option<ResourceExpr>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    imports: PythonImportNames,
    /// Module-level functions, for summarizing and applying calls into them.
    defs: Vec<PythonFunctionDef>,
    summaries: std::collections::HashMap<String, Summary>,
    demand_summaries: bool,
    summary_in_progress: HashSet<String>,
    summary_cycles: HashSet<String>,
    summary_refining: bool,
    summary_spans: std::collections::HashMap<String, Vec<TextRange>>,
    summary_effect_sources: HashMap<String, HashMap<usize, Rc<ProvenanceKind>>>,
    /// Body summaries retained behind decorator gates for repository composition.
    decorated_summaries: std::collections::HashMap<String, Summary>,
    /// Deferred subprocesses for same-file summary application, keyed by name.
    spawn_summaries: std::collections::HashMap<String, Vec<CapturedSpawn>>,
    /// Module-level path constants (`ROOT = "/var/cache"`), resolved once.
    consts: std::collections::HashMap<String, ResourceExpr>,
    shared_vars: HashSet<String>,
    /// Module constants whose value came from Python string concatenation.
    const_concatenations: HashSet<String>,
    /// Module constants that cannot be used as bounded string components.
    const_unbounded_strings: HashSet<String>,
    /// Names in the current scope resolved to a resource expression: seeded
    /// from `consts`, then extended as locals are assigned a resolvable value
    /// or the substituted return of a summarized function. A bare name that
    /// appears here resolves to its bound resource instead of a free parameter.
    var_scope: std::collections::HashMap<String, ResourceExpr>,
    /// Names whose current value is rooted in a pathlib constructor or one of
    /// its path-producing operations.
    path_vars: HashSet<String>,
    /// Path receiver names whose control-flow alternatives include a non-path
    /// value, so only unambiguous pathlib methods may dispatch at the join.
    branch_mixed_path_vars: HashSet<String>,
    /// Current bindings whose resource was lowered from `+` or an f-string.
    concatenated_vars: HashSet<String>,
    /// Current bindings that cannot be used as bounded string components.
    unbounded_string_vars: HashSet<String>,
    /// Exact finite sequence or mapping values retained from literal
    /// containers and bounded comprehensions.
    collections: std::collections::HashMap<String, StaticContainer>,
    /// Names whose control-flow alternatives disagree. A later effect use
    /// widens rather than treating the name like a free parameter.
    widened_vars: HashSet<String>,
    /// Local names bound to a constructed network object (`s =
    /// requests.Session()`, `conn = http.client.HTTPConnection(host)`), so a
    /// later `s.get(url)` / `conn.request(...)` resolves to a network effect.
    sessions: std::collections::HashMap<String, Receiver>,
    modeled_values: std::collections::HashMap<String, model::ModeledValue>,
    /// Immutable bytes are bounded by the source, shared across loop evaluations.
    literal_bytes: RefCell<std::collections::HashMap<TextRange, Rc<Vec<u8>>>>,
    /// The write effect each binary-mode `open(...)`, `io.open(...)` or
    /// `Path.open(...)` call emitted, by the call's range, and the open call
    /// each name is bound to, so a later `f.write(data)` can mark the write
    /// it stores into.
    open_writes: std::collections::HashMap<TextRange, u32>,
    write_handles: std::collections::HashMap<String, TextRange>,
    /// Local functions that return a constructed network object, by name, so a
    /// call `s = build_requests_session()` binds `s` to a session even though
    /// the constructor is hidden behind the helper's return.
    return_receivers: std::collections::HashMap<String, ReceiverKind>,
    /// Local sockets that called `connect`, by name, with the endpoint.
    connected_sockets: std::collections::HashMap<String, ResourceExpr>,
    /// The `network.connect` of the socket this process's standard input was
    /// replaced with (`os.dup2(s.fileno(), 0)`): a program spawned afterwards
    /// reads its input from that connection.
    stdin_connection: Option<u32>,
    /// Calls that run on every pass of an enclosing loop or comprehension
    /// over a literal integer sequence holding 0, as the call in `for fd in
    /// (0, 1, 2): os.dup2(s.fileno(), fd)` does: the call's start offset and
    /// the loop variable. A call under a filter or an `if` is not one.
    zero_loop_calls: std::collections::HashMap<u32, String>,
    /// Exact class returned by a same-file factory on every return path.
    return_instances: std::collections::HashMap<String, String>,
    /// Module receiver environment used by the current summary fixpoint.
    summary_instances: std::collections::HashMap<String, SemanticValue>,
    /// Constructor identities in finite, locally bound iterables.
    instance_sequences: std::collections::HashMap<String, Vec<Option<SemanticValue>>>,
    /// When set, effects/boundaries/coverage are collected into this buffer
    /// (summary inference) instead of emitted to the plan (execution).
    capture: Option<PythonSummaryCapture>,
    capture_condition_depth: usize,
    /// Whether module execution entered any declared function or method.
    entered_callables: bool,
    /// Import-grounded framework decorators that preserve their function body.
    framework_decorators: HashSet<String>,
    registration_spans: HashSet<(u32, u32)>,
    /// Unresolved callees already reported, to bound boundary output.
    reported_unresolved: HashSet<(String, TextRange)>,
    nodes_left: u64,
    node_budget_hit: bool,
    /// An effect argument read a name that this execution never bound.
    free_resource_parameter: Cell<bool>,
    walk_depth: u32,
    /// Local names bound to the flow stage whose produced value they hold, so a
    /// later use of the name as a call argument wires a def-use edge. Reassigning
    /// the name to a non-producer drops the binding.
    flow_vars: std::collections::HashMap<String, usize>,
    /// Buffered flow stages and edges (local stage ids), committed to the plan
    /// only when at least one edge formed — a plan with no def-use keeps its
    /// graph omitted and serializes unchanged.
    stage_writer: StageWriter,
    /// Parameter names of the function whose body is currently being captured,
    /// so a call to a parameter can be recorded as a callback-shaped edge.
    current_params: Vec<String>,
    /// Internal identity of the function currently being summarized. Nested
    /// closure names resolve only inside their lexical parent.
    current_function: Option<String>,
    /// Parameters whose exact annotation resolves to `pathlib.Path`.
    current_path_params: HashSet<String>,
    /// Class owning the function currently being captured.
    current_class: Option<String>,
    /// Names of classes defined at this module's top level, for classifying
    /// constructor calls and class-qualified method receivers.
    class_names: HashSet<String>,
    /// Written bases of each local class, used for exact `super().method()`.
    class_bases: std::collections::HashMap<String, Vec<String>>,
    /// Instance attributes initialized by a direct constructor call.
    path_attrs: Vec<(String, String, String)>,
    /// Resource-valued instance attributes assigned by local class initializers.
    attr_values: Vec<PythonInitAttrValue>,
    /// Literal string constants declared directly on a class.
    class_strings: std::collections::HashMap<(String, String), String>,
    /// Module constants that are finite tuples of written class names.
    class_sets: std::collections::HashMap<String, Vec<String>>,
    /// Loop variables currently ranging over one of those finite tuples.
    class_set_vars: std::collections::HashMap<String, Vec<String>>,
    /// Capture mode: locals bound to an unambiguous constructor (`loader =
    /// DataLoader()`, `cli = cls(args)`), so method calls and arguments carry
    /// a typed receiver/instance.
    instance_vars: std::collections::HashMap<String, SemanticValue>,
    /// Constructor-derived attributes invalidated by writes through a tracked
    /// local instance.
    instance_attr_rebindings: std::collections::HashMap<String, HashSet<String>>,
    /// Capture mode: locals assigned from a user-call result, typed at
    /// composition time via the callee's `returns_instances`.
    bound_vars: HashSet<String>,
    /// Receiver names explicitly rebound while joining alternative branches.
    receiver_rebindings: HashSet<String>,
    /// Capture mode: the assignment currently being walked, keyed by its RHS
    /// call's span — the recorded edge for that call gets these `binds`.
    pending_binds: Option<(TextRange, Vec<(usize, String)>)>,
    /// Capture mode: exact call edges stored directly in a literal container.
    deferred_containers: std::collections::HashMap<String, Vec<usize>>,
    /// Capture mode: loop variables currently bound to those container elements.
    deferred_vars: std::collections::HashMap<String, Vec<usize>>,
    /// The literal-container assignment currently being walked.
    pending_deferred_container: Option<(String, Vec<TextRange>)>,
    /// The call an expression statement discards, so a coroutine it makes
    /// never runs.
    discarded_call: Option<TextRange>,
    /// Whether this source may change the working directory anywhere, so a
    /// coroutine run after it is made may inherit another directory.
    source_changes_cwd: bool,
    /// Repository context for deterministic Effect IR facts. Plan-only walks
    /// leave the scope absent because they do not emit module summaries.
    fact_file: String,
    fact_scope: Option<ScopeKey>,
    fact_function: String,
    site_ordinal: Cell<u32>,
    site_origins: RefCell<std::collections::HashMap<TextRange, ValueOrigin>>,
    module_capture: bool,
    /// True while an await, iteration, or context-manager protocol executes a
    /// deferred async/generator body.
    execute_deferred: bool,
    /// The exact outer call whose result is consumed. Non-call deferred roots
    /// leave this unset; local generators are handled separately.
    deferred_call: Option<TextRange>,
    /// A consumed call that is awaited or handed straight to a scheduler that
    /// runs it (`asyncio.run`, `create_task`, `gather`, ...), rather than to a
    /// lazy wrapper such as `wait_for` whose own coroutine may never run.
    eager_call: Option<TextRange>,
    /// An eager call consumed where it is made (awaited, or passed to
    /// `asyncio.run` or `run_until_complete`), so it runs before anything
    /// after it; a scheduled one may run after later statements.
    synchronous_call: Option<TextRange>,
    /// Launch search roots for invocation import traversal. None keeps imports
    /// as dependency-request boundaries (repository indexing links modules).
    import_search: Option<imports::PythonImportSearch>,
    /// Summaries of imported functions reached by calls, keyed by
    /// [`imports::imported_summary_key`].
    imported_summaries: std::collections::HashMap<String, Rc<imports::ImportedFunction>>,
    /// Guarantees of summaries applied since the enclosing call began.
    control_applications: Vec<SiteFacts>,
    /// What each current summary guarantees to a same-file caller.
    summary_requirements: std::collections::HashMap<String, Requirements>,
    /// The summary effects each callable prints to stdout.
    summary_stdout: std::collections::HashMap<String, Vec<u32>>,
    /// The value flows among each callable's summary effects.
    summary_flows: std::collections::HashMap<String, Vec<(u32, u32)>>,
    /// The summary effects each callable's parameters flow into; `None` is
    /// the program's stdout.
    summary_param_flows: std::collections::HashMap<String, Vec<(String, Option<u32>)>>,
    /// The parameter flows of the summary just applied, in the slots its
    /// effects landed in, until the call that applied it binds arguments.
    applied_param_flows: Vec<(String, Option<u32>)>,
    /// Plan effects (`None` for stdout) a same-file call's arguments flow
    /// into, by argument position, with that call's span, from the call's
    /// summary until the call takes them to wire its arguments.
    argument_consumers: Option<(TextRange, ArgumentConsumers)>,
    /// What each callable leaves in its caller's bindings.
    summary_writes: std::collections::HashMap<String, Vec<SummaryWrite>>,
    /// The writes of the summary just applied, in the slots its effects
    /// landed in, until the call that applied it binds them.
    applied_writes: Vec<SummaryWrite>,
    /// The writes a same-file call walked outside a summary leaves, with
    /// that call's span and callee, until the call has walked its arguments.
    pending_writes: Option<(TextRange, String, Vec<SummaryWrite>)>,
    /// The producers each element of a literal container a module-level
    /// name holds carries, with the stage `flow_vars` held for the name at
    /// the binding: they stand only while it still holds that stage.
    flow_elements: std::collections::HashMap<String, (Option<usize>, ConstantElements)>,
    /// What each callable's reachable returns pass back.
    summary_returns: std::collections::HashMap<String, Vec<ReturnSite>>,
    /// What each same-file call walked outside a summary returns, in plan
    /// effects, by the call's span, until its value is bound.
    call_returns: std::collections::HashMap<TextRange, Vec<CallReturn>>,
    /// Module-level names that shadow builtins, including assignments and imports.
    module_binds: HashSet<String>,
    /// Every name the module's top level binds or a function declares
    /// `global`: what a function body reads when it names something it does
    /// not bind itself.
    module_names: HashSet<String>,
    /// The `environment.read` effects whose value each plan flow stage
    /// carries.
    environment_stages: std::collections::HashMap<usize, Vec<u32>>,
    /// What each name holds of the whole environment (`env =
    /// dict(os.environ)`); see `printed_environment.rs`.
    environment_holds: std::collections::HashMap<String, printed_environment::EnvironmentHold>,
    /// The shape `environment_holds` assumes a call gives a summarized
    /// body's parameters in: the mapping, except while a change is applied
    /// to another reading (`each_given`).
    environment_given: printed_environment::EnvironmentShape,
    /// What each callable does with the environment values it is given.
    summary_environment: std::collections::HashMap<String, printed_environment::EnvironmentSummary>,
    /// What each parameter default held when its `def` ran, by the
    /// default expression's span: a default is evaluated once, there.
    default_values: std::collections::HashMap<String, dataflow_capture::DefaultValue>,
    /// The class bodies being walked, outermost first, each with what the
    /// enclosing scope's bindings hold meanwhile under the names it binds.
    class_outer: Vec<dataflow_capture::OuterNames>,
    /// How many same-file calls have been applied.
    local_calls_applied: u64,
    /// Whether the program has replaced an environment value, after which a
    /// value the host supplied no longer describes what a read sees.
    environment_rewritten: bool,
    /// The names the program has set in its environment so far. A child it
    /// launches inherits them; their values are not tracked here.
    written_environment: BTreeSet<String>,
    ipython: Option<ipython::IpythonState>,
}

impl PythonWalker<'_, '_> {
    fn charge_steps(&mut self, steps: u64, span: (u32, u32)) -> bool {
        crate::limits::summary_steps(steps).unwrap_or_else(|| {
            crate::nest::charge_analysis_steps(self.builder, self.nest.budget, steps, Some(span))
        })
    }

    /// Charge one node against the frontend cap and the whole-analysis step
    /// budget; false once either is exhausted.
    fn charge(&mut self, range: TextRange) -> bool {
        let span = (u32::from(range.start()), u32::from(range.end()));
        if self.demand_summaries && self.capture.is_some() && self.nodes_left == 0 {
            if !self.node_budget_hit {
                self.node_budget_hit = true;
                let node = self.span_node(range);
                self.out_boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    affected_resource: None,
                    callee: None,
                    provenance: vec![node],
                    limit: Some("max_python_nodes".into()),
                    detail: self.current_function.clone(),
                });
            }
            return false;
        }
        if !self.charge_steps(1, span) {
            self.node_budget_hit = true;
            return false;
        }
        if self.nodes_left == 0 {
            if !self.node_budget_hit {
                self.node_budget_hit = true;
                python_boundary(
                    self.builder,
                    self.scope,
                    BoundaryReason::LIMIT_SATURATED,
                    BoundaryClass::Limit,
                    Some("max_python_nodes"),
                    None,
                );
            }
            return false;
        }
        self.nodes_left -= 1;
        true
    }

    fn partial_walk(&mut self) {
        if self.node_budget_hit {
            return;
        }
        self.node_budget_hit = true;
        python_boundary(
            self.builder,
            self.scope,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            Some("max_walk_depth"),
            Some("python walk depth bound reached".to_string()),
        );
    }

    //
    // An expression that produces an effect is a flow stage; the value it
    // returns is its `Value` port. Tracking `var = <producer>` remembers the
    // stage, and a later use of `var` as an argument to another producing call
    // emits a `data_flow` edge from the producer's `Value` to the consumer's
    // `Arg(n)`.
    // Conservative and structural: local variables within this walk only, no
    // aliasing, container-element, or cross-function return propagation.
}

fn python_boundary(
    builder: &mut PlanBuilder,
    scope: Option<ProvenanceRef>,
    reason: BoundaryReason,
    class: BoundaryClass,
    limit_name: Option<&str>,
    detail: Option<String>,
) {
    builder.boundary(Boundary {
        reason,
        class,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: scope.as_slice().to_vec(),
        limit: limit_name.map(str::to_string),
        detail,
    });
}
