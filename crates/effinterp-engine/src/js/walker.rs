//! The JavaScript execution walk: prepare semantic evidence, visit the program, then commit its flow.

use std::collections::{HashMap, HashSet};

use effinterp_proto::{
    CoverageLevel, Domain, ProvenanceKind, ProvenanceRef, ResourceExpr, SourceDialect,
};
use oxc_ast::ast::Statement;
use oxc_ast_visit::Visit;
use oxc_semantic::SemanticBuilder;
use oxc_span::{GetSpan, Span};

use super::aggregate_alias::{AggregateAliasPaths, AggregateAliases, EvaluatedAggregateAliases};
use super::bindings::{self, Bindings};
use super::call_body::{ActiveBody, FlowCapture, runs_unwritten_calls};
use super::callable_bindings::CallableEnv;
use super::callback_dispatch::throws_reject;
use super::class_initializers::uninstantiated_class_spans;
use super::collect::{self, FnTable};
use super::console::{self, ConsoleAssignment, ConsoleBindingWrite};
use super::flow_tracking::{self, FlowShape, ResponseKind};
use super::guard_regions::js_guard_regions;
use super::identifier_references::{
    global_reference_spans, process_alias_references, readonly_write_spans,
    runtime_missing_identifier_spans,
};
use super::resolve::{self, ParamEnv};
use super::source_string::{
    EvaluatedSourceStrings, SourceStringValue, collect_source_string_bindings,
};
use super::source_string_state::{SourceStringNames, SourceStringState};
use super::{JS_DOMAINS, control, model, module_load, printed_environment};
use crate::builder::PlanBuilder;
use crate::control_flow::SiteFacts;
use crate::flow::StageWriter;
use crate::lang::frontend::{FrontendInput, WalkOutcome};
use crate::nest::Nest;

/// Walk the module's executed statements. Function bodies enter only through a reached call.
pub(super) fn walk_js_program<'a>(
    builder: &mut PlanBuilder,
    nest: &Nest,
    input: &FrontendInput,
    program: &oxc_ast::ast::Program<'a>,
    dialect: SourceDialect,
) -> WalkOutcome {
    let source_cwd = input.source_cwd;
    let runtime_cwd = input.runtime_cwd;
    let cwd_node = input.cwd_node;
    let scope = input.scope;
    let depth = input.depth;
    let semantic = SemanticBuilder::new().build(program).semantic;
    let scoping = semantic.scoping();
    let runtime_missing_identifier_spans = runtime_missing_identifier_spans(&semantic);
    let process_references = process_alias_references(program, &semantic);
    let global_require_spans = module_load::global_require_spans(&semantic);
    let throws_reject = throws_reject(program, input.source);
    let _process_aliases = resolve::ProcessAliases::enter(process_references.clone());
    let runtime = model::JsRuntime::launched_by(builder.launching_command());
    // `deno eval` runs its code as an ES module, which has no `require`;
    // a Deno file may still be CommonJS.
    let require_shadowed = (runtime == model::JsRuntime::Deno
        && nest
            .script_origins
            .borrow()
            .last()
            .is_none_or(Option::is_none))
        || scoping.get_root_binding("require".into()).is_some()
        || builder.js_eval_require_shadowed();
    let module_loads = module_load::collect(
        program,
        &semantic,
        require_shadowed,
        &global_require_spans,
        nest.current_source_cwd(),
    );
    let mut bindings = Bindings {
        throws_reject,
        readonly_writes: readonly_write_spans(&semantic),
        source_digest: effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
            &input.source,
        ),
        require_shadowed,
        loaded_literals: module_loads.loaded_literals.clone(),
        global_process_spans: process_references
            .iter()
            .map(|(span, _)| *span)
            .chain(global_reference_spans(&semantic, "process"))
            .collect(),
        console: console::console_aliases(program, &semantic),
        // A write to the global itself replaces it for every reader.
        runtime_code_spans: ["eval", "Function"]
            .into_iter()
            .flat_map(|name| global_reference_spans(&semantic, name))
            .collect(),
        runtime_text_spans: bindings::TEXT_GLOBALS
            .into_iter()
            .flat_map(|name| global_reference_spans(&semantic, name))
            .collect(),
        posix_environment: builder.path_platform() == effinterp_proto::PathPlatform::Posix,
        uninstantiated_classes: uninstantiated_class_spans(&semantic),
        ..Bindings::default()
    };
    bindings.visit_program(program);
    bindings.guards = js_guard_regions(program, input.source, throws_reject, &bindings);
    bindings.dynamic_imports = resolve::DynamicImportFacts::collect(program);
    let _literal_environment = resolve::LiteralEnvironmentScope::enter(
        bindings
            .environment_rewrites_are_literal()
            .then(|| resolve::LiteralEnvironment {
                writes: bindings
                    .literal_env_writes
                    .iter()
                    .map(|(span, (name, value))| (*span, name.clone(), value.clone()))
                    .collect(),
                bodies: bindings.body_spans.clone(),
            }),
    );
    let functions = collect::collect(program);
    let runtime_cwd_resource = builder.current_execution_cwd();
    let cwd_consts = resolve::collect_consts(program, None, source_cwd, &bindings);
    // `process.argv` holds the interpreter, then the script unless the
    // launch runs inline code, then the operands.
    let first_operand = if builder.current_launch_is_inline() {
        1
    } else {
        2
    };
    let module_env: ParamEnv = builder
        .current_execution_argv()
        .iter()
        .enumerate()
        .skip(first_operand)
        .filter(|(index, _)| {
            bindings.process_runtime()
                && !bindings.member_was_reassigned(&format!("process.argv.{index}"))
        })
        .map(|(index, value)| (format!("process.argv[{index}]"), value.clone()))
        .collect();
    let source_strings = module_env.clone();
    let unbounded_strings: SourceStringNames = collect_source_string_bindings(&program.body)
        .into_iter()
        .collect();
    let callable_bindings = CallableEnv::new();
    let unwritten_calls = runs_unwritten_calls(&semantic);

    let max_nodes = nest.limits.max_js_nodes;
    let first_effect = builder.effects_len();
    let entry_condition_depth = builder.condition_depth();
    let completion = builder
        .prints_completion()
        .then(|| {
            program.body.iter().rev().find(|statement| {
                !matches!(
                    statement,
                    Statement::VariableDeclaration(_)
                        | Statement::FunctionDeclaration(_)
                        | Statement::EmptyStatement(_)
                )
            })
        })
        .flatten();
    let mut effects = JsWalker {
        completion_statement: completion
            .filter(|statement| matches!(statement, Statement::ExpressionStatement(_)))
            .map(GetSpan::span),
        condition_site: (0, 0),
        console_assignments: Vec::new(),
        console_binding_writes: Vec::new(),
        builder,
        nest,
        source_cwd,
        runtime_cwd,
        runtime_cwd_resource,
        cwd_node,
        chdir: None,
        entry_condition_depth,
        runtime,
        scope,
        depth,
        bindings: &bindings,
        scoping,
        module_loads,
        runtime_missing_identifier_spans: &runtime_missing_identifier_spans,
        env_write_spans: &bindings.env_write_spans,
        process_runtime: bindings.process_runtime(),
        dialect,
        unsupported_process_receiver_reported: false,
        written_environment: Default::default(),
        functions: &functions,
        plus_coercion_callbacks: &functions.plus_coercion_callbacks,
        visiting: HashSet::new(),
        active_bodies: Vec::new(),
        block_bindings: Vec::new(),
        shadowed_bindings: Vec::new(),
        exception_source_states: Vec::new(),
        exception_regions: Vec::new(),
        return_source_states: Vec::new(),
        return_source_values: Vec::new(),
        return_aggregate_aliases: Vec::new(),
        source_string_write_names: Vec::new(),
        param_env: module_env.clone(),
        module_env,
        source_env: source_strings.clone(),
        source_strings,
        unbounded_source_env: unbounded_strings.clone(),
        unbounded_source_strings: unbounded_strings,
        definitely_nullish_env: SourceStringNames::new(),
        module_definitely_nullish_env: SourceStringNames::new(),
        callable_env: callable_bindings.clone(),
        module_callable_env: callable_bindings,
        aggregate_aliases: AggregateAliases::new(),
        module_aggregate_aliases: AggregateAliases::new(),
        evaluated_source_strings: EvaluatedSourceStrings::new(),
        evaluated_aggregate_aliases: EvaluatedAggregateAliases::new(),
        class_super_plus_coercions: HashMap::new(),
        labeled_switches: Vec::new(),
        instantiable_classes: Vec::new(),
        function_depth: 0,
        entered_callable_body: false,
        cwd_param_env: cwd_consts.clone(),
        cwd_consts,
        charged_source_state: None,
        server_vars: HashSet::new(),
        object_literal_vars: model::ObjectLiteralBindings::new(),
        module_object_literal_vars: model::ObjectLiteralBindings::new(),
        decoded_literal_vars: HashMap::new(),
        nodes: 0,
        max_nodes,
        saturated: false,
        depth_stopped: false,
        walk_depth: 0,
        flow_vars: HashMap::new(),
        flow_slots: HashSet::new(),
        flow_shapes: HashMap::new(),
        flow_slots_saturated: false,
        return_producers: Vec::new(),
        stage_by_span: HashMap::new(),
        environment_stages: HashMap::new(),
        environment_holds: HashMap::new(),
        environment_params: None,
        call_callee: None,
        environment_result_followed: false,
        own_statement: None,
        direct_statement: None,
        statement_depth: 0,
        certain_body: None,
        unwritten_calls,
        callback_seed: None,
        callback_captures: None,
        enclosing_flows: Vec::new(),
        callback_producer: None,
        response_vars: HashMap::new(),
        compiled_vars: HashMap::new(),
        stage_writer: StageWriter::default(),
        control_source: input.source,
        control_applications: Vec::new(),
    };
    effects.builder.control_enter(input.source, false, |graph| {
        control::build_program(graph, program, &bindings.readonly_writes)
    });
    effects.visit_program(program);
    if let Some(statement) = completion
        && !matches!(
            statement,
            Statement::ExpressionStatement(_) | Statement::ThrowStatement(_)
        )
    {
        effects.unmodeled_dynamic(
            statement.span(),
            "program completion value is not followed through this statement",
        );
    }
    effects.builder.control_leave();
    effects.stage_writer.commit(effects.builder);
    let entered_callable_body = effects.entered_callable_body;
    drop(effects);
    let declared_callables = if !functions.declared_callables().is_empty()
        && !entered_callable_body
        && builder.effects_len() == first_effect
    {
        functions.declared_callables().to_vec()
    } else {
        Vec::new()
    };
    for domain in JS_DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    WalkOutcome { declared_callables }
}

pub(super) struct JsWalker<'v, 'a> {
    pub(super) completion_statement: Option<Span>,
    pub(super) condition_site: (u32, u32),
    /// Earlier assignments, `delete`s and escapes of runtime `console`
    /// methods, each with the path state it ran under, in program order.
    pub(super) console_assignments: Vec<ConsoleAssignment>,
    /// Earlier writes of the bindings that may hold a console method (see
    /// [`console::ConsoleAliases::bindings`]), in program order.
    pub(super) console_binding_writes: Vec<ConsoleBindingWrite>,
    pub(super) builder: &'v mut PlanBuilder,
    pub(super) nest: &'v Nest<'v>,
    pub(super) source_cwd: Option<&'v str>,
    pub(super) runtime_cwd: Option<&'v str>,
    pub(super) runtime_cwd_resource: Option<ResourceExpr>,
    pub(super) cwd_node: Option<ProvenanceRef>,
    /// The directory a proven `chdir` entered; later relative paths, child
    /// processes and evaluated source run there.
    pub(super) chdir: Option<String>,
    /// Conditions the enclosing executions held when this walk began, so a
    /// chdir is judged only by the program's own branches.
    pub(super) entry_condition_depth: usize,
    /// The runtime whose globals (`Deno`, `Bun`) the program can call.
    pub(super) runtime: model::JsRuntime,
    pub(super) scope: Option<ProvenanceRef>,
    pub(super) depth: u64,
    pub(super) bindings: &'v Bindings,
    pub(super) scoping: &'v oxc_semantic::Scoping,
    /// Loader calls classified before the walk. A call absent from this map
    /// is not a module load.
    pub(super) module_loads: module_load::ModuleLoads,
    /// Identifier reads that can fail because no binding exists at runtime.
    pub(super) runtime_missing_identifier_spans: &'v HashSet<u32>,
    pub(super) env_write_spans: &'v HashSet<u32>,
    pub(super) process_runtime: bool,
    /// The dialect this program was parsed with, so source it evaluates at
    /// runtime is entered under the same grammar.
    pub(super) dialect: SourceDialect,
    pub(super) unsupported_process_receiver_reported: bool,
    /// The names the program has set through `process.env` so far. A child
    /// it launches inherits them; their values are not tracked here.
    pub(super) written_environment: std::collections::BTreeSet<String>,
    pub(super) functions: &'v FnTable<'a>,
    pub(super) plus_coercion_callbacks: &'v collect::PlusCoercionTable<'a>,
    /// Bodies currently on the reachability stack, to break call cycles.
    pub(super) visiting: HashSet<u32>,
    /// Lexically active bodies and their enclosing state, used to seed a
    /// nested callee without leaking locals from an intervening caller.
    pub(super) active_bodies: Vec<ActiveBody>,
    /// The block statements being walked and the names each declares,
    /// innermost last. Entering a called body keeps only the blocks that
    /// lexically enclose it.
    pub(super) block_bindings: Vec<(Span, HashSet<String>)>,
    /// The scopes being walked that redeclare names of an outer scope
    /// (a block, a loop head, a catch parameter), innermost last, each with
    /// what the outer bindings of those names hold meanwhile.
    pub(super) shadowed_bindings: Vec<(Span, flow_tracking::ShadowedBindings)>,
    /// Source-string states reaching explicit throws in the active try block.
    pub(super) exception_source_states: Vec<Vec<SourceStringState>>,
    /// Starts of the try blocks and catch clauses being walked, innermost
    /// last: a throw may skip or select the statements in them.
    pub(super) exception_regions: Vec<u32>,
    /// Source-string states reaching returns in each entered function body.
    pub(super) return_source_states: Vec<Vec<SourceStringState>>,
    /// Source-string values returned by each entered function body.
    pub(super) return_source_values: Vec<Vec<SourceStringValue>>,
    /// Caller-visible aggregate aliases returned by each entered function body.
    pub(super) return_aggregate_aliases: Vec<AggregateAliasPaths>,
    /// Binding names changed by each currently executing function body.
    pub(super) source_string_write_names: Vec<HashSet<String>>,
    /// The current scope's name -> resource bindings: module constants, the
    /// current function's parameter -> caller-argument bindings, and locals
    /// assigned a resolvable value (a path literal, or a call into a local
    /// function whose return resolves), so a later use of the name resolves.
    pub(super) param_env: ParamEnv,
    /// Live module-level resource bindings. Kept separate from `param_env` so
    /// entering a function does not leak the caller's locals.
    pub(super) module_env: ParamEnv,
    /// Untyped source strings remain separate from filesystem-resolved values
    /// so a consuming network sink can still recognize a URL literal.
    pub(super) source_env: ParamEnv,
    /// Live module-level source strings used to seed each entered function scope.
    pub(super) source_strings: ParamEnv,
    /// Names whose current value cannot be bounded as a string. They make a
    /// surrounding concatenation fail instead of becoming a free parameter.
    pub(super) unbounded_source_env: SourceStringNames,
    /// Live module-level unbounded names used to seed each entered function scope.
    pub(super) unbounded_source_strings: SourceStringNames,
    /// Names whose current value is proven null or undefined.
    pub(super) definitely_nullish_env: SourceStringNames,
    /// Live module-level definitely-nullish names used to seed entered functions.
    pub(super) module_definitely_nullish_env: SourceStringNames,
    /// Executed assignments that supersede statically collected callable declarations.
    pub(super) callable_env: CallableEnv,
    /// Live module-level callable assignments used to seed entered functions.
    pub(super) module_callable_env: CallableEnv,
    /// Aggregate bindings that may refer to the same object or array.
    pub(super) aggregate_aliases: AggregateAliases,
    /// Live module-level aggregate aliases used to seed entered functions.
    pub(super) module_aggregate_aliases: AggregateAliases,
    /// Source strings captured when their operands evaluate, before later
    /// operands can mutate a binding they already read.
    pub(super) evaluated_source_strings: EvaluatedSourceStrings,
    /// Aggregate aliases returned by evaluated local calls.
    pub(super) evaluated_aggregate_aliases: EvaluatedAggregateAliases,
    /// Class span -> superclass coercion owner fixed when the class is evaluated.
    pub(super) class_super_plus_coercions: HashMap<u32, u32>,
    /// Labels attached directly to switches currently being visited.
    pub(super) labeled_switches: Vec<(u32, String)>,
    /// For each class being walked, innermost last, whether it may be
    /// instantiated, which runs its instance field initializers.
    pub(super) instantiable_classes: Vec<bool>,
    /// Function nesting distinguishes module assignments, which update the
    /// live snapshots above, from local assignments.
    pub(super) function_depth: u32,
    /// Whether execution entered any function, method, callback, or IIFE body.
    pub(super) entered_callable_body: bool,
    /// Bindings resolved without a runtime cwd, used only to decide whether a
    /// filesystem effect's provenance must include the runtime cwd.
    pub(super) cwd_param_env: ParamEnv,
    pub(super) cwd_consts: ParamEnv,
    /// The last retained snapshot charged to `max_analysis_bytes`; later
    /// snapshots are charged only for the entries they add or change.
    pub(super) charged_source_state: Option<SourceStringState>,
    pub(super) nodes: u64,
    pub(super) max_nodes: u64,
    pub(super) saturated: bool,
    pub(super) walk_depth: u32,
    /// Whether a node past the walk-depth bound was skipped, which is
    /// reported once.
    pub(super) depth_stopped: bool,
    /// Local names bound to a server handle (`const server =
    /// httpServer.createServer(...)`), so a later `server.listen(...)` is a
    /// network bind.
    pub(super) server_vars: HashSet<String>,
    pub(super) object_literal_vars: model::ObjectLiteralBindings,
    pub(super) module_object_literal_vars: model::ObjectLiteralBindings,
    /// `const` names bound to bytes a write would store (`Buffer.from` of a
    /// literal), for `model::decoded_literal_bytes`.
    pub(super) decoded_literal_vars: HashMap<String, Vec<u8>>,
    /// Local names bound to the flow stage whose produced value they hold, so a
    /// later use of the name as a call argument wires a def-use edge.
    pub(super) flow_vars: HashMap<String, usize>,
    /// Exact bindings and collection slots, including values that are not
    /// producers. This lets a later safe spread overwrite stale producer data.
    pub(super) flow_slots: HashSet<String>,
    /// Collection bindings whose complete shape is statically known.
    pub(super) flow_shapes: HashMap<String, FlowShape>,
    pub(super) flow_slots_saturated: bool,
    /// Producer observations for returns in each currently entered body.
    pub(super) return_producers: Vec<Vec<Option<usize>>>,
    /// Expression span-start -> the flow stage created for that expression's
    /// effects, so a producer nested directly in an argument (or bound to a
    /// variable) can be linked after it is walked.
    pub(super) stage_by_span: HashMap<u32, usize>,
    /// The `environment.read` effects whose value each flow stage carries.
    pub(super) environment_stages: HashMap<usize, Vec<u32>>,
    /// What each binding holds of the whole environment (`const e =
    /// process.env`); see `printed_environment.rs`.
    pub(super) environment_holds: HashMap<String, printed_environment::EnvironmentShape>,
    /// What the parameters of the body about to be entered, named by its
    /// span start, hold of the whole environment.
    pub(super) environment_params:
        Option<(u32, Vec<(String, printed_environment::EnvironmentShape)>)>,
    pub(super) call_callee: Option<Span>,
    pub(super) environment_result_followed: bool,
    /// Span start of the expression the statement being walked consists of:
    /// an assignment or a call that starts there runs whenever the
    /// statement does, where one nested in `a && b` or `a ? b : c` may not.
    pub(super) own_statement: Option<u32>,
    /// The same, for a statement written directly in the program or in
    /// the function body being walked, which runs on every path through
    /// it, where one inside a branch, loop or `try` may not.
    pub(super) direct_statement: Option<u32>,
    /// How many statements enclose the one being walked within the
    /// current body.
    pub(super) statement_depth: u32,
    /// The body, named by its span start, that a call about to be entered
    /// certainly runs to its end before the caller's next statement: a
    /// direct call that is a statement of its own to a function that is
    /// not async. Only such a body's clear of an enclosing binding, and
    /// what it leaves that binding holding of the environment, reaches the
    /// caller.
    pub(super) certain_body: Option<u32>,
    /// Whether the program may run a body or replace a function where no
    /// call is written (`runs_unwritten_calls`): no call is certain then.
    pub(super) unwritten_calls: bool,
    /// The producer a callback's first parameter receives, keyed by the
    /// callback body it is seeded into, and whether that value is a response
    /// object.
    pub(super) callback_seed: Option<(u32, String, usize, Option<ResponseKind>)>,
    /// Tracked locals an `http(s).get` `end` listener reads, keyed by the
    /// listener body they are seeded into.
    pub(super) callback_captures: Option<(u32, Vec<FlowCapture>)>,
    /// What each enclosing scope's tracked locals held when it called into
    /// the next: the module first, then each of `active_bodies` but the
    /// innermost. A body reads the ones of the scopes it is written inside.
    pub(super) enclosing_flows: Vec<Vec<FlowCapture>>,
    /// Locals holding a response object. It carries the fetched bytes only
    /// through a body read or a `data` listener, so the object itself is not
    /// source code.
    pub(super) response_vars: HashMap<String, ResponseKind>,
    /// Locals bound to a function compiled from code (`const f = new
    /// Function(t)`): the body depth of the binding and the producers of the
    /// code, which runs where the local is called.
    pub(super) compiled_vars: HashMap<String, (usize, Vec<usize>)>,
    /// The producer the last followed callback returned.
    pub(super) callback_producer: Option<usize>,
    /// Buffered flow stages and edges (local stage ids), committed to the plan
    /// only when at least one edge formed.
    pub(super) stage_writer: StageWriter,
    /// The analyzed source, keying this walk's control-flow frames.
    pub(super) control_source: &'v str,
    /// Guarantees of function bodies entered since the enclosing call began.
    pub(super) control_applications: Vec<SiteFacts>,
}

impl<'a> JsWalker<'_, 'a> {
    pub(super) fn span_node(&mut self, span: Span) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: span.start,
                end: span.end,
            },
            self.scope.as_slice(),
        )
    }
}
