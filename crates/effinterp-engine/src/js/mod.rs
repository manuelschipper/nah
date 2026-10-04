//! Effect-directed JavaScript/TypeScript frontend.
//!
//! Uses the `oxc` parser (pinned to 0.116, the last release building on this
//! toolchain) to produce an AST, then walks it looking only for calls that
//! reach effect boundaries: `fs`, `child_process`, `http`/`https`/`fetch`,
//! and `process.env`. Module ownership is tracked through imports and
//! `require`, so a bare `.rm(...)` on an unknown object never triggers a
//! model. Everything unresolved — dynamic `require`, `eval`, `Function`,
//! computed access, non-literal values — becomes a typed boundary rather
//! than a guessed effect. TypeScript is parsed with the same API by turning
//! on the TS source type; type annotations are ignored.
//!
//! ## Execution, not source presence
//!
//! The plan describes what EXECUTING the module does, not the union of
//! effects present anywhere in source. A function body contributes effects
//! only when a call reaches it: top-level statements run, and calls into
//! locally defined functions, immediately-invoked function expressions, and
//! callbacks passed as arguments are followed transitively (bounded, with a
//! cycle guard). A defined-but-never-called function contributes nothing.
//! Callbacks are followed conservatively — a missed real effect is worse for
//! a security-adjacent consumer than an over-reported `may`. A call that
//! resolves to neither a modeled API nor a local function, and whose callee
//! is not a known-inert builtin, records an `unresolved_call` boundary
//! spanning every domain it could reach, so it is never silently dropped.

mod aggregate_alias;
mod aggregate_source_string_members;
mod ast_visit;
mod bindings;
mod collect;
mod console;
mod control;
mod destructuring_defaults;
mod flow_tracking;
mod model;
mod plus_coercion;
mod resolve;
mod source_string;
mod source_string_state;
mod summarize;

use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
use crate::value::unresolved_resource;
use bindings::{
    AssignmentTargetBindings, Bindings, binding_declares, collect_binding_names,
    collect_scope_binding_names, function_local_binding_names,
};
pub(crate) use model::is_node_builtin_module;

use std::collections::{HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference, CoverageLevel, Domain,
    Effect, ProvenanceKind, ProvenanceRef, ResourceExpr, SourceDialect,
};
use im::{HashMap as PersistentHashMap, HashSet as PersistentHashSet};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentTarget, BindingPattern, BlockStatement,
    CallExpression, CatchClause, ChainElement, ClassBody, ClassElement, Expression, ForInStatement,
    ForOfStatement, ForStatement, FormalParameters, FunctionBody, IfStatement, MemberExpression,
    MethodDefinition, NewExpression, ObjectProperty, PropertyDefinition, PropertyKey,
    SimpleAssignmentTarget, Statement, SwitchStatement, TaggedTemplateExpression,
    VariableDeclaration, VariableDeclarationKind, WhileStatement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::{GetSpan, SourceType, Span};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::{ControlExit, SiteFacts};
use crate::flow::StageWriter;
use crate::nest::Nest;
use crate::summary::bind_positional;
use aggregate_alias::{
    AggregateAliasPaths, EvaluatedAggregateAliases, aggregate_alias_binding_names,
    clear_aggregate_aliases, expression_aggregate_alias_paths, extend_aggregate_alias_paths,
};
use aggregate_source_string_members::collect_aggregate_source_string_members;
use collect::FnTable;
use plus_coercion::{PLUS_COERCION_BINDING_SUFFIX, plus_coercion_binding_name};
use resolve::ParamEnv;
use source_string::{
    EvaluatedSourceStrings, SourceBindingValue, SourceStringValue, bind_source_string_pattern,
    collect_source_string_bindings, is_global_undefined, is_home_directory_call,
    is_string_concatenation, mark_unbounded_source_string, set_source_string_binding,
    source_string_resource,
};
use source_string_state::{
    SourceStringState, changed_captured_bindings, object_literal_bytes,
    restore_source_string_state_names,
};

const JS_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

const MAX_FLOW_SLOTS: usize = 512;

/// The effects a call into a modeled external JS module performs, for
/// cross-file composition: a repo-file re-export chain may end at an external
/// module (zx's `export const fs = wrap('fs', _fs)`), and the composer then
/// needs the modeled effect for `<module>.<function>` at the original call
/// site. `args` are the caller's already-lowered argument resources. None when
/// the module/function pair is not modeled — the caller must stay loud.
pub fn js_external_effects(
    module: &str,
    function: &str,
    args: &[ResourceExpr],
) -> Option<Vec<Effect>> {
    model::external_effects(module, function, args)
}

/// Whether the module runs a call while it loads: a top-level expression
/// statement (or `export default <expression>`) that evaluates a call outside
/// any function body. Discovery uses this parser-owned answer to recognize
/// scripts whose only module-scope work is a call the semantic summaries omit,
/// such as `console.log('loaded')` or a bootstrap IIFE. Declarations and calls
/// that only appear inside an uncalled body are not module-scope execution.
/// Returns None when a parse error prevents reliable root classification.
pub fn js_runs_module_scope_call(source: &str) -> Option<bool> {
    if crate::lang::depth::js_nesting_exceeds(source) {
        return None;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    if !parsed.errors.is_empty() {
        return None;
    }
    Some(parsed.program.body.iter().any(|statement| {
        let expression = match statement {
            Statement::ExpressionStatement(statement) => &statement.expression,
            Statement::ExportDefaultDeclaration(export) => {
                match export.declaration.as_expression() {
                    Some(expression) => expression,
                    None => return false,
                }
            }
            _ => return false,
        };
        let mut calls = ModuleScopeCalls::default();
        calls.visit_expression(expression);
        calls.found
    }))
}

/// Finds a call evaluated by the expression it visits, without entering the
/// function bodies, parameter defaults, or class bodies that only run later.
#[derive(Default)]
struct ModuleScopeCalls {
    found: bool,
    walk_depth: u32,
}

impl<'a> Visit<'a> for ModuleScopeCalls {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.found || self.walk_depth >= MAX_WALK_DEPTH {
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_call_expression(&mut self, _it: &CallExpression<'a>) {
        self.found = true;
    }

    fn visit_new_expression(&mut self, _it: &NewExpression<'a>) {
        self.found = true;
    }

    fn visit_tagged_template_expression(&mut self, _it: &TaggedTemplateExpression<'a>) {
        self.found = true;
    }

    fn visit_function_body(&mut self, _it: &FunctionBody<'a>) {}

    fn visit_formal_parameters(&mut self, _it: &FormalParameters<'a>) {}

    fn visit_class_body(&mut self, _it: &ClassBody<'a>) {}
}

/// Literal static imports executed while one JavaScript module initializes.
pub(crate) fn runtime_imports(source: &str, dialect: SourceDialect) -> Option<Vec<String>> {
    if crate::lang::depth::js_nesting_exceeds(source) {
        return None;
    }
    let allocator = Allocator::default();
    let source_type = match dialect {
        SourceDialect::Js => SourceType::mjs(),
        SourceDialect::Ts => SourceType::ts(),
        SourceDialect::Ipython | SourceDialect::PrimeAgent => {
            unreachable!("validated JavaScript dialect")
        }
    };
    let parsed = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty().then(|| {
        parsed
            .program
            .body
            .iter()
            .filter_map(|statement| match statement {
                Statement::ImportDeclaration(import) if !import.import_kind.is_type() => {
                    Some(import.source.value.as_str().to_string())
                }
                _ => None,
            })
            .collect()
    })
}

pub(crate) struct JsFrontend {
    pub allocator: Allocator,
    pub dialect: SourceDialect,
}

impl Frontend for JsFrontend {
    const LANGUAGE: &'static str = "js";
    const DOMAINS: &'static [&'static str] = &JS_DOMAINS;
    type Ast<'a> = oxc_ast::ast::Program<'a>;
    fn nesting_exceeds(&self, source: &str) -> bool {
        crate::lang::depth::js_nesting_exceeds(source)
    }
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let source_type = match self.dialect {
            SourceDialect::Js => SourceType::mjs(),
            SourceDialect::Ts => SourceType::ts(),
            SourceDialect::Ipython | SourceDialect::PrimeAgent => {
                unreachable!("validated JavaScript dialect")
            }
        };
        let parsed = Parser::new(&self.allocator, source, source_type).parse();
        let failure = parsed.errors.first().map(|err| ParseFailure {
            detail: err.to_string(),
        });
        ParseOutcome {
            ast: Some(parsed.program),
            failure,
        }
    }
    fn parse_failure(
        &self,
        builder: &mut PlanBuilder,
        scope: Option<ProvenanceRef>,
        failure: &ParseFailure,
    ) {
        for domain in JS_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::PARSE_ERROR,
            class: BoundaryClass::ParseFailure,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: scope.as_slice().to_vec(),
            limit: None,
            detail: Some(failure.detail.clone()),
        });
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        program: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let source_cwd = input.source_cwd;
        let runtime_cwd = input.runtime_cwd;
        let cwd_node = input.cwd_node;
        let scope = input.scope;
        let depth = input.depth;
        let semantic = SemanticBuilder::new().build(program).semantic;
        let scoping = semantic.scoping();
        let can_throw = |reference_id| {
            let reference = scoping.get_reference(reference_id);
            reference.is_read()
        };
        let mut runtime_missing_identifier_spans: HashSet<_> = scoping
            .root_unresolved_references()
            .iter()
            .filter(|(name, _)| !model::RUNTIME_GLOBALS.contains(&name.as_str()))
            .flat_map(|(_, reference_ids)| reference_ids.iter().copied())
            .filter(|reference_id| can_throw(*reference_id))
            .map(|reference_id| {
                semantic
                    .reference_span(scoping.get_reference(reference_id))
                    .start
            })
            .collect();
        for symbol_id in scoping
            .symbol_ids()
            .filter(|symbol_id| scoping.symbol_flags(*symbol_id).is_ambient())
            .filter(|symbol_id| !model::RUNTIME_GLOBALS.contains(&scoping.symbol_name(*symbol_id)))
        {
            runtime_missing_identifier_spans.extend(
                scoping
                    .get_resolved_reference_ids(symbol_id)
                    .iter()
                    .copied()
                    .filter(|reference_id| can_throw(*reference_id))
                    .map(|reference_id| {
                        semantic
                            .reference_span(scoping.get_reference(reference_id))
                            .start
                    }),
            );
        }
        let process_references = process_alias_references(program, &semantic);
        let throws_reject = throws_reject(program, input.source);
        let _process_aliases = resolve::ProcessAliases::enter(process_references.clone());
        let runtime = model::JsRuntime::launched_by(builder.launching_command());
        let mut bindings = Bindings {
            throws_reject,
            readonly_writes: readonly_write_spans(&semantic),
            source_digest: effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN,
                &input.source,
            ),
            // `deno eval` runs its code as an ES module, which has no
            // `require`; a Deno file may still be CommonJS.
            require_shadowed: (runtime == model::JsRuntime::Deno
                && nest
                    .script_origins
                    .borrow()
                    .last()
                    .is_none_or(Option::is_none))
                || scoping.get_root_binding("require".into()).is_some(),
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
        let module_env: ParamEnv = builder
            .current_execution_argv()
            .iter()
            .enumerate()
            .skip(2)
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

        let max_nodes = nest.limits.max_js_nodes;
        let first_effect = builder.effects_len();
        let entry_condition_depth = builder.condition_depth();
        let mut effects = EffectVisitor {
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
            runtime_missing_identifier_spans: &runtime_missing_identifier_spans,
            env_write_spans: &bindings.env_write_spans,
            process_runtime: bindings.process_runtime(),
            dialect: self.dialect,
            unsupported_process_receiver_reported: false,
            functions: &functions,
            plus_coercion_callbacks: &functions.plus_coercion_callbacks,
            visiting: HashSet::new(),
            active_bodies: Vec::new(),
            block_bindings: Vec::new(),
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
            nodes: 0,
            max_nodes,
            saturated: false,
            walk_depth: 0,
            flow_vars: HashMap::new(),
            flow_slots: HashSet::new(),
            flow_shapes: HashMap::new(),
            flow_slots_saturated: false,
            return_producers: Vec::new(),
            stage_by_span: HashMap::new(),
            callback_seed: None,
            callback_captures: None,
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
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summarize::summarize_ast(source, ast, file, scope)
    }
}

#[derive(Clone, Copy)]
enum SequentialStop {
    SwitchBreak,
    Abrupt,
}

fn statement_sequential_stop(statement: &Statement<'_>) -> Option<SequentialStop> {
    statement_sequential_stop_in_switch(statement, None)
}

fn statement_sequential_stop_in_switch(
    statement: &Statement<'_>,
    switch_label: Option<&str>,
) -> Option<SequentialStop> {
    match statement {
        Statement::BreakStatement(statement) => Some(
            if statement.label.as_ref().is_none_or(|label| {
                switch_label.is_some_and(|switch_label| label.name.as_str() == switch_label)
            }) {
                SequentialStop::SwitchBreak
            } else {
                SequentialStop::Abrupt
            },
        ),
        Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_)
        | Statement::ContinueStatement(_) => Some(SequentialStop::Abrupt),
        Statement::BlockStatement(block) => block
            .body
            .iter()
            .find_map(|statement| statement_sequential_stop_in_switch(statement, switch_label)),
        Statement::IfStatement(branch) => {
            let alternate = branch.alternate.as_ref()?;
            let consequent = statement_sequential_stop_in_switch(&branch.consequent, switch_label)?;
            let alternate = statement_sequential_stop_in_switch(alternate, switch_label)?;
            if matches!(consequent, SequentialStop::SwitchBreak)
                || matches!(alternate, SequentialStop::SwitchBreak)
            {
                Some(SequentialStop::SwitchBreak)
            } else {
                Some(SequentialStop::Abrupt)
            }
        }
        Statement::TryStatement(statement) => {
            if let Some(finalizer) = &statement.finalizer
                && let Some(stop) = finalizer.body.iter().find_map(|statement| {
                    statement_sequential_stop_in_switch(statement, switch_label)
                })
            {
                return Some(stop);
            }
            let block = statement.block.body.iter().find_map(|statement| {
                statement_sequential_stop_in_switch(statement, switch_label)
            })?;
            let Some(handler) = &statement.handler else {
                return Some(block);
            };
            let handler = handler.body.body.iter().find_map(|statement| {
                statement_sequential_stop_in_switch(statement, switch_label)
            })?;
            if matches!(block, SequentialStop::SwitchBreak)
                || matches!(handler, SequentialStop::SwitchBreak)
            {
                Some(SequentialStop::SwitchBreak)
            } else {
                Some(SequentialStop::Abrupt)
            }
        }
        Statement::SwitchStatement(statement) => {
            if !statement.cases.iter().any(|case| case.test.is_none()) {
                return None;
            }
            let mut suffix_stop = None;
            for case in statement.cases.iter().rev() {
                if let Some(stop) = case.consequent.iter().find_map(|statement| {
                    statement_sequential_stop_in_switch(statement, switch_label)
                }) {
                    suffix_stop = Some(stop);
                }
                if !matches!(suffix_stop, Some(SequentialStop::Abrupt)) {
                    return None;
                }
            }
            Some(SequentialStop::Abrupt)
        }
        _ => None,
    }
}

fn statement_stops_sequential_execution(statement: &Statement<'_>) -> bool {
    statement_sequential_stop(statement).is_some()
}

/// A resolved effect API callee: a function `fn` on a known `module`.
struct ModuleCall {
    module: String,
    function: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowShape {
    Object,
    Array(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallableBinding {
    Assigned(u32),
    Declarator(u32),
    PlusCoercion(u32),
    Unbounded,
}

// Persistent execution environments make scope snapshots share unchanged bindings.
type CallableEnv = PersistentHashMap<String, CallableBinding>;
type AggregateAliases = PersistentHashMap<String, HashSet<String>>;
type SourceStringNames = PersistentHashSet<String>;

fn binding_is_within(binding: &str, name: &str) -> bool {
    binding == name
        || binding
            .strip_prefix(name)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn binding_names_with_descendants<'a>(
    names: &HashSet<String>,
    candidates: impl Iterator<Item = &'a String>,
) -> HashSet<String> {
    let mut expanded = names.clone();
    expanded.extend(
        candidates
            .filter(|candidate| names.iter().any(|name| binding_is_within(candidate, name)))
            .cloned(),
    );
    expanded
}

fn resolve_callable<'t, 'a>(
    functions: &'t FnTable<'a>,
    callable_env: &CallableEnv,
    name: &str,
    use_span: Span,
) -> Option<&'t collect::FnInfo<'a>> {
    match callable_env.get(name) {
        Some(CallableBinding::Assigned(assignment_span)) => {
            collect::resolve_assignment(functions, name, *assignment_span)
        }
        Some(CallableBinding::Declarator(initialized_at)) => {
            collect::resolve_declarator(functions, name, *initialized_at)
        }
        Some(CallableBinding::PlusCoercion(_)) => None,
        Some(CallableBinding::Unbounded) => None,
        None => collect::resolve(functions, name, use_span),
    }
}

/// What a local holding a response object is: a fetch `Response`, which
/// yields its bytes through a body read such as `.text()`, or the message an
/// `http(s).get` response handler receives, which streams them to `data`
/// listeners.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseKind {
    Fetch,
    Message,
}

/// A tracked local seeded into a callback: its name, its producer, and
/// whether it holds a response object.
type FlowCapture = (String, usize, Option<ResponseKind>);

/// A callback through which file or response bytes become available.
enum MessageHandler {
    /// The handler passed to `get`, whose first parameter is the message.
    Response,
    /// The callback runs after the read; its second parameter holds the file
    /// bytes when the read succeeded.
    File,
    /// A `data` listener, whose first parameter is a chunk of the body.
    Chunk,
    /// An `end` listener, which runs after every chunk arrived, so it reads
    /// whatever the `data` listeners accumulated.
    End,
}

struct ActiveBody {
    span: Span,
    enclosing_source_state: SourceStringState,
    local_names: HashSet<String>,
    process_runtime: bool,
}

#[derive(Default)]
struct BodyResult {
    producer: Option<usize>,
    source_return: Option<SourceStringValue>,
    aggregate_return: AggregateAliasPaths,
}

/// References, by span start and name, to each `const` local initialized to
/// the runtime's own `process`. Any other alias stays unknown.
fn process_alias_references(
    program: &oxc_ast::ast::Program<'_>,
    semantic: &oxc_semantic::Semantic<'_>,
) -> HashSet<(u32, String)> {
    struct Aliases<'s> {
        global: HashSet<u32>,
        symbols: Vec<(oxc_semantic::SymbolId, &'s str)>,
        depth: u32,
    }
    impl<'a> Visit<'a> for Aliases<'a> {
        fn visit_statement(&mut self, it: &Statement<'a>) {
            // Past the depth limit an alias is simply not recognized.
            if self.depth >= MAX_WALK_DEPTH {
                return;
            }
            self.depth += 1;
            walk::walk_statement(self, it);
            self.depth -= 1;
        }
        fn visit_expression(&mut self, it: &Expression<'a>) {
            if self.depth >= MAX_WALK_DEPTH {
                return;
            }
            self.depth += 1;
            walk::walk_expression(self, it);
            self.depth -= 1;
        }
        fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
            if it.kind == VariableDeclarationKind::Const {
                for declarator in &it.declarations {
                    if let BindingPattern::BindingIdentifier(alias) = &declarator.id
                        && let Some(Expression::Identifier(process)) =
                            declarator.init.as_ref().map(unparen)
                        && process.name.as_str() == "process"
                        && self.global.contains(&process.span.start)
                        && let Some(symbol) = alias.symbol_id.get()
                    {
                        self.symbols.push((symbol, alias.name.as_str()));
                    }
                }
            }
            walk::walk_variable_declaration(self, it);
        }
    }
    let mut aliases = Aliases {
        global: global_reference_spans(semantic, "process"),
        symbols: Vec::new(),
        depth: 0,
    };
    aliases.visit_program(program);
    let scoping = semantic.scoping();
    aliases
        .symbols
        .into_iter()
        .flat_map(|(symbol, name)| {
            scoping
                .get_resolved_reference_ids(symbol)
                .iter()
                .map(move |reference| {
                    let span = semantic.reference_span(scoping.get_reference(*reference));
                    (span.start, name.to_string())
                })
        })
        .collect()
}

/// Spans of the references to `name` that no scope binds, so they reach the
/// runtime's global. Empty when the program writes that global.
fn global_reference_spans(semantic: &oxc_semantic::Semantic<'_>, name: &str) -> HashSet<u32> {
    let scoping = semantic.scoping();
    let Some(references) = scoping.root_unresolved_references().get(name) else {
        return HashSet::new();
    };
    let references = references
        .iter()
        .map(|reference| scoping.get_reference(*reference))
        .collect::<Vec<_>>();
    if references.iter().any(|reference| reference.is_write()) {
        return HashSet::new();
    }
    references
        .into_iter()
        .map(|reference| semantic.reference_span(reference).start)
        .collect()
}

/// Span starts of class declarations that nothing can instantiate: ambient
/// declarations, and unexported, undecorated ones whose name no value
/// expression references, even from inside the class, and whose static
/// initializers never use `this`, which is the class there (`new this()`).
/// A reference only as a TypeScript type constructs nothing. Any other class
/// may be instantiated.
fn uninstantiated_class_spans(semantic: &oxc_semantic::Semantic<'_>) -> HashSet<u32> {
    /// Whether code that runs with the class as `this` uses it. A nested
    /// non-arrow function binds its own `this`.
    #[derive(Default)]
    struct UsesThis(bool);
    impl<'a> Visit<'a> for UsesThis {
        fn visit_this_expression(&mut self, _it: &oxc_ast::ast::ThisExpression) {
            self.0 = true;
        }
        fn visit_function(
            &mut self,
            _it: &oxc_ast::ast::Function<'a>,
            _flags: oxc_semantic::ScopeFlags,
        ) {
        }
    }
    let nodes = semantic.nodes();
    let scoping = semantic.scoping();
    nodes
        .iter()
        .filter_map(|node| {
            let oxc_ast::AstKind::Class(class) = node.kind() else {
                return None;
            };
            if class.declare {
                return Some(class.span.start);
            }
            let id = class.id.as_ref().filter(|_| class.is_declaration())?;
            if matches!(
                nodes.parent_kind(node.id()),
                oxc_ast::AstKind::ExportNamedDeclaration(_)
                    | oxc_ast::AstKind::ExportDefaultDeclaration(_)
            ) || !class.decorators.is_empty()
            {
                return None;
            }
            let mut uses_this = UsesThis::default();
            for element in &class.body.body {
                match element {
                    ClassElement::StaticBlock(block) => uses_this.visit_static_block(block),
                    ClassElement::PropertyDefinition(property) if property.r#static => {
                        if let Some(value) = &property.value {
                            uses_this.visit_expression(value);
                        }
                    }
                    ClassElement::AccessorProperty(property) if property.r#static => {
                        if let Some(value) = &property.value {
                            uses_this.visit_expression(value);
                        }
                    }
                    _ => {}
                }
                let decorated = match element {
                    ClassElement::MethodDefinition(method) => !method.decorators.is_empty(),
                    ClassElement::PropertyDefinition(property) => !property.decorators.is_empty(),
                    ClassElement::AccessorProperty(property) => !property.decorators.is_empty(),
                    _ => false,
                };
                if decorated {
                    return None;
                }
            }
            if uses_this.0 {
                return None;
            }
            scoping
                .get_resolved_reference_ids(id.symbol_id())
                .iter()
                .all(|reference| !scoping.get_reference(*reference).is_value())
                .then_some(class.span.start)
        })
        .collect()
}

fn readonly_write_spans(semantic: &oxc_semantic::Semantic<'_>) -> Option<HashSet<u32>> {
    let limit = crate::AnalysisLimits::default().max_causal_pairs;
    if semantic.nodes().len() as u64 > limit {
        return None;
    }
    let scoping = semantic.scoping();
    let mut spans = HashSet::new();
    for symbol in scoping.symbol_ids() {
        if !crate::limits::summary_step() {
            return None;
        }
        if !scoping.symbol_flags(symbol).is_const_variable() {
            continue;
        }
        for reference in scoping.get_resolved_reference_ids(symbol) {
            if !crate::limits::summary_step() {
                return None;
            }
            let reference = scoping.get_reference(*reference);
            if reference.is_write() {
                spans.insert(semantic.reference_span(reference).start);
            }
        }
    }
    Some(spans)
}

/// The truth of an `if` test that is a literal, whose other arm never runs.
fn literal_truth(test: &Expression<'_>) -> Option<bool> {
    match unparen(test) {
        Expression::BooleanLiteral(literal) => Some(literal.value),
        Expression::NullLiteral(_) => Some(false),
        Expression::NumericLiteral(literal) => {
            Some(literal.value != 0.0 && !literal.value.is_nan())
        }
        _ => None,
    }
}

/// The arguments whose bytes `console.log` prints, a spread's operand
/// among them. A literal format string drops a `%c` argument as CSS; a
/// number conversion (`%d`, `%i`, `%f`) keeps whatever digits it holds, so
/// those arguments still count as printed. A spread of a literal array
/// expands in place; after a spread of unknown length no position is known,
/// so every later value counts as printed.
fn console_printed_arguments<'b, 'a>(arguments: &'b [Argument<'a>]) -> Vec<&'b Expression<'a>> {
    // Values at known positions (`None` for an array hole), then the
    // operands past the first spread of unknown length.
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for argument in arguments {
        match argument {
            Argument::SpreadElement(spread) => {
                if !(unknown.is_empty() && expand_literal_spread(&spread.argument, &mut known)) {
                    unknown.push(&spread.argument);
                }
            }
            _ => {
                if let Some(expression) = argument.as_expression() {
                    if unknown.is_empty() {
                        known.push(Some(expression));
                    } else {
                        unknown.push(expression);
                    }
                }
            }
        }
    }
    let mut dropped = HashSet::new();
    if let Some(Some(Expression::StringLiteral(format))) = known.first() {
        let mut next = 1;
        let mut characters = format.value.chars();
        while let Some(character) = characters.next() {
            if character != '%' {
                continue;
            }
            match characters.next() {
                Some('s' | 'j' | 'o' | 'O' | 'd' | 'i' | 'f') => next += 1,
                Some('c') => {
                    dropped.insert(next);
                    next += 1;
                }
                _ => {}
            }
        }
    }
    known
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !dropped.contains(index))
        .filter_map(|(_, value)| value)
        .chain(unknown)
        .collect()
}

/// Append the values a spread of `expression` passes when it is a literal
/// array whose length is known; false, appending nothing, otherwise.
fn expand_literal_spread<'b, 'a>(
    expression: &'b Expression<'a>,
    values: &mut Vec<Option<&'b Expression<'a>>>,
) -> bool {
    let Expression::ArrayExpression(array) = unparen(expression) else {
        return false;
    };
    let mut expanded = Vec::new();
    for element in &array.elements {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                if !expand_literal_spread(&spread.argument, &mut expanded) {
                    return false;
                }
            }
            ArrayExpressionElement::Elision(_) => expanded.push(None),
            _ => expanded.push(element.as_expression()),
        }
    }
    values.extend(expanded);
    true
}

/// Def-use tracking at the entry of a conditionally executed construct.
struct FlowEntry {
    vars: HashMap<String, usize>,
    slots: HashSet<String>,
    shapes: HashMap<String, FlowShape>,
    compiled: HashMap<String, (usize, Vec<usize>)>,
}

/// Resolve only evidence introduced by this function. `None` leaves the
/// caller to supply the lexically enclosing process receiver.
fn function_process_scope(
    body: &FunctionBody<'_>,
    parameters: &FormalParameters<'_>,
) -> Option<bool> {
    if formal_parameters_declare_process(parameters) {
        return Some(false);
    }
    let mut locals = Bindings::default();
    for statement in &body.statements {
        locals.visit_statement(statement);
    }
    if locals.process_bindings == 0 && !locals.process_reassigned {
        None
    } else {
        Some(locals.process_runtime())
    }
}

fn formal_parameters_declare_process(parameters: &FormalParameters<'_>) -> bool {
    parameters
        .items
        .iter()
        .any(|parameter| binding_declares(&parameter.pattern, "process"))
        || parameters
            .rest
            .as_ref()
            .is_some_and(|rest| binding_declares(&rest.rest.argument, "process"))
}

fn member_producer(expression: &Expression<'_>) -> Option<String> {
    match unparen(expression) {
        Expression::NewExpression(new) => match unparen(&new.callee) {
            Expression::Identifier(callee) => Some(callee.name.as_str().to_string()),
            _ => None,
        },
        Expression::CallExpression(call) => match unparen(&call.callee) {
            Expression::Identifier(callee) => Some(callee.name.as_str().to_string()),
            _ => None,
        },
        Expression::AwaitExpression(awaited) => member_producer(&awaited.argument),
        _ => None,
    }
}

fn clear_bound_pattern(
    pattern: &oxc_ast::ast::BindingPattern<'_>,
    namespaces: &mut HashMap<String, String>,
    named: &mut HashMap<String, (String, String)>,
    default_imports: &mut HashSet<String>,
    member_producers: &mut HashMap<String, String>,
) {
    use oxc_ast::ast::BindingPattern;
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            namespaces.remove(id.name.as_str());
            named.remove(id.name.as_str());
            default_imports.remove(id.name.as_str());
            member_producers.remove(id.name.as_str());
        }
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                clear_bound_pattern(
                    &property.value,
                    namespaces,
                    named,
                    default_imports,
                    member_producers,
                );
            }
            if let Some(rest) = &object.rest {
                clear_bound_pattern(
                    &rest.argument,
                    namespaces,
                    named,
                    default_imports,
                    member_producers,
                );
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in array.elements.iter().flatten() {
                clear_bound_pattern(
                    element,
                    namespaces,
                    named,
                    default_imports,
                    member_producers,
                );
            }
            if let Some(rest) = &array.rest {
                clear_bound_pattern(
                    &rest.argument,
                    namespaces,
                    named,
                    default_imports,
                    member_producers,
                );
            }
        }
        BindingPattern::AssignmentPattern(assignment) => clear_bound_pattern(
            &assignment.left,
            namespaces,
            named,
            default_imports,
            member_producers,
        ),
    }
}

/// How the frontend evaluated a call, for its control-flow site.
#[derive(Clone, Copy)]
enum JsCall {
    /// A modeled API or known-inert callee.
    Modeled,
    /// A same-file body entered at the call.
    Local,
    /// Code the frontend cannot see, which may complete the invocation.
    Opaque,
}

/// What following a call reached: the call itself, the bodies it entered
/// directly (the first `direct` recorded applications), and how many callback
/// arguments were followed after them.
struct Reached {
    call: JsCall,
    direct: usize,
    callbacks: usize,
}

/// An assignment of a runtime `console` method, or an escape of the console
/// that may rewrite any of them, and the path state it ran under: its
/// condition and the enclosing try and catch regions.
struct ConsoleAssignment {
    /// The method assigned; `None` for any method.
    method: Option<String>,
    /// Whether the value assigned provably writes nothing to stdout. Any
    /// other value may print.
    silences: bool,
    condition: Option<effinterp_proto::Condition>,
    regions: Vec<u32>,
}

/// A write of a binding that may hold a console method: whether the value
/// may print to stdout, and the path state it ran under.
struct ConsoleBindingWrite {
    symbol: oxc_semantic::SymbolId,
    prints: bool,
    condition: Option<effinterp_proto::Condition>,
    regions: Vec<u32>,
}

struct EffectVisitor<'v, 'a> {
    condition_site: (u32, u32),
    /// Earlier assignments, `delete`s and escapes of runtime `console`
    /// methods, each with the path state it ran under, in program order.
    console_assignments: Vec<ConsoleAssignment>,
    /// Earlier writes of the bindings that may hold a console method (see
    /// [`console::ConsoleAliases::bindings`]), in program order.
    console_binding_writes: Vec<ConsoleBindingWrite>,
    builder: &'v mut PlanBuilder,
    nest: &'v Nest<'v>,
    source_cwd: Option<&'v str>,
    runtime_cwd: Option<&'v str>,
    runtime_cwd_resource: Option<ResourceExpr>,
    cwd_node: Option<ProvenanceRef>,
    /// The directory a proven `chdir` entered; later relative paths, child
    /// processes and evaluated source run there.
    chdir: Option<String>,
    /// Conditions the enclosing executions held when this walk began, so a
    /// chdir is judged only by the program's own branches.
    entry_condition_depth: usize,
    /// The runtime whose globals (`Deno`, `Bun`) the program can call.
    runtime: model::JsRuntime,
    scope: Option<ProvenanceRef>,
    depth: u64,
    bindings: &'v Bindings,
    /// Identifier reads that can fail because no binding exists at runtime.
    runtime_missing_identifier_spans: &'v HashSet<u32>,
    env_write_spans: &'v HashSet<u32>,
    process_runtime: bool,
    /// The dialect this program was parsed with, so source it evaluates at
    /// runtime is entered under the same grammar.
    dialect: SourceDialect,
    unsupported_process_receiver_reported: bool,
    functions: &'v FnTable<'a>,
    plus_coercion_callbacks: &'v collect::PlusCoercionTable<'a>,
    /// Bodies currently on the reachability stack, to break call cycles.
    visiting: HashSet<u32>,
    /// Lexically active bodies and their enclosing state, used to seed a
    /// nested callee without leaking locals from an intervening caller.
    active_bodies: Vec<ActiveBody>,
    /// The block statements being walked and the names each declares,
    /// innermost last. Entering a called body keeps only the blocks that
    /// lexically enclose it.
    block_bindings: Vec<(Span, HashSet<String>)>,
    /// Source-string states reaching explicit throws in the active try block.
    exception_source_states: Vec<Vec<SourceStringState>>,
    /// Starts of the try blocks and catch clauses being walked, innermost
    /// last: a throw may skip or select the statements in them.
    exception_regions: Vec<u32>,
    /// Source-string states reaching returns in each entered function body.
    return_source_states: Vec<Vec<SourceStringState>>,
    /// Source-string values returned by each entered function body.
    return_source_values: Vec<Vec<SourceStringValue>>,
    /// Caller-visible aggregate aliases returned by each entered function body.
    return_aggregate_aliases: Vec<AggregateAliasPaths>,
    /// Binding names changed by each currently executing function body.
    source_string_write_names: Vec<HashSet<String>>,
    /// The current scope's name -> resource bindings: module constants, the
    /// current function's parameter -> caller-argument bindings, and locals
    /// assigned a resolvable value (a path literal, or a call into a local
    /// function whose return resolves), so a later use of the name resolves.
    param_env: ParamEnv,
    /// Live module-level resource bindings. Kept separate from `param_env` so
    /// entering a function does not leak the caller's locals.
    module_env: ParamEnv,
    /// Untyped source strings remain separate from filesystem-resolved values
    /// so a consuming network sink can still recognize a URL literal.
    source_env: ParamEnv,
    /// Live module-level source strings used to seed each entered function scope.
    source_strings: ParamEnv,
    /// Names whose current value cannot be bounded as a string. They make a
    /// surrounding concatenation fail instead of becoming a free parameter.
    unbounded_source_env: SourceStringNames,
    /// Live module-level unbounded names used to seed each entered function scope.
    unbounded_source_strings: SourceStringNames,
    /// Names whose current value is proven null or undefined.
    definitely_nullish_env: SourceStringNames,
    /// Live module-level definitely-nullish names used to seed entered functions.
    module_definitely_nullish_env: SourceStringNames,
    /// Executed assignments that supersede statically collected callable declarations.
    callable_env: CallableEnv,
    /// Live module-level callable assignments used to seed entered functions.
    module_callable_env: CallableEnv,
    /// Aggregate bindings that may refer to the same object or array.
    aggregate_aliases: AggregateAliases,
    /// Live module-level aggregate aliases used to seed entered functions.
    module_aggregate_aliases: AggregateAliases,
    /// Source strings captured when their operands evaluate, before later
    /// operands can mutate a binding they already read.
    evaluated_source_strings: EvaluatedSourceStrings,
    /// Aggregate aliases returned by evaluated local calls.
    evaluated_aggregate_aliases: EvaluatedAggregateAliases,
    /// Class span -> superclass coercion owner fixed when the class is evaluated.
    class_super_plus_coercions: HashMap<u32, u32>,
    /// Labels attached directly to switches currently being visited.
    labeled_switches: Vec<(u32, String)>,
    /// For each class being walked, innermost last, whether it may be
    /// instantiated, which runs its instance field initializers.
    instantiable_classes: Vec<bool>,
    /// Function nesting distinguishes module assignments, which update the
    /// live snapshots above, from local assignments.
    function_depth: u32,
    /// Whether execution entered any function, method, callback, or IIFE body.
    entered_callable_body: bool,
    /// Bindings resolved without a runtime cwd, used only to decide whether a
    /// filesystem effect's provenance must include the runtime cwd.
    cwd_param_env: ParamEnv,
    cwd_consts: ParamEnv,
    /// The last retained snapshot charged to `max_analysis_bytes`; later
    /// snapshots are charged only for the entries they add or change.
    charged_source_state: Option<SourceStringState>,
    nodes: u64,
    max_nodes: u64,
    saturated: bool,
    walk_depth: u32,
    /// Local names bound to a server handle (`const server =
    /// httpServer.createServer(...)`), so a later `server.listen(...)` is a
    /// network bind.
    server_vars: HashSet<String>,
    object_literal_vars: model::ObjectLiteralBindings,
    module_object_literal_vars: model::ObjectLiteralBindings,
    /// Local names bound to the flow stage whose produced value they hold, so a
    /// later use of the name as a call argument wires a def-use edge.
    flow_vars: HashMap<String, usize>,
    /// Exact bindings and collection slots, including values that are not
    /// producers. This lets a later safe spread overwrite stale producer data.
    flow_slots: HashSet<String>,
    /// Collection bindings whose complete shape is statically known.
    flow_shapes: HashMap<String, FlowShape>,
    flow_slots_saturated: bool,
    /// Producer observations for returns in each currently entered body.
    return_producers: Vec<Vec<Option<usize>>>,
    /// Expression span-start -> the flow stage created for that expression's
    /// effects, so a producer nested directly in an argument (or bound to a
    /// variable) can be linked after it is walked.
    stage_by_span: HashMap<u32, usize>,
    /// The producer a callback's first parameter receives, keyed by the
    /// callback body it is seeded into, and whether that value is a response
    /// object.
    callback_seed: Option<(u32, String, usize, Option<ResponseKind>)>,
    /// Tracked locals an `http(s).get` `end` listener reads, keyed by the
    /// listener body they are seeded into; see [`MessageHandler::End`].
    callback_captures: Option<(u32, Vec<FlowCapture>)>,
    /// Locals holding a response object. It carries the fetched bytes only
    /// through a body read or a `data` listener, so the object itself is not
    /// source code.
    response_vars: HashMap<String, ResponseKind>,
    /// Locals bound to a function compiled from code (`const f = new
    /// Function(t)`): the body depth of the binding and the producers of the
    /// code, which runs where the local is called.
    compiled_vars: HashMap<String, (usize, Vec<usize>)>,
    /// The producer the last followed callback returned.
    callback_producer: Option<usize>,
    /// Buffered flow stages and edges (local stage ids), committed to the plan
    /// only when at least one edge formed.
    stage_writer: StageWriter,
    /// The analyzed source, keying this walk's control-flow frames.
    control_source: &'v str,
    /// Guarantees of function bodies entered since the enclosing call began.
    control_applications: Vec<SiteFacts>,
}

impl<'a> EffectVisitor<'_, 'a> {
    /// Follow a call into the code it actually reaches: a locally defined
    /// function, an immediately-invoked function/arrow, or a followed
    /// callback argument. A call resolving to none of these — and not a
    /// modeled API or inert built-in — records an `unresolved_call` boundary.
    fn follow_reachable(
        &mut self,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) -> Reached {
        if self.bindings.dynamic_imports.is_quiet_call(call) {
            let mut callbacks = 0;
            for arg in &call.arguments {
                if let Some(expr) = arg.as_expression() {
                    callbacks += usize::from(self.follow_callback(expr));
                }
            }
            return Reached {
                call: JsCall::Modeled,
                direct: 0,
                callbacks,
            };
        }
        let original_callee = unparen(&call.callee);
        let callee = sequence_callee_value(original_callee);
        let quiet_promise = self.is_quiet_promise_callee(original_callee);

        let known = |visitor: &Self| visitor.is_modeled_call(call) || visitor.is_quiet_callee(call);
        // Immediately-invoked function/arrow: its body executes now.
        let reached = match callee {
            Expression::FunctionExpression(f) => {
                if f.generator {
                    JsCall::Modeled
                } else if let Some(body) = &f.body {
                    let self_binding = f.id.as_ref().map(|id| id.name.as_str());
                    let result = self.enter_inline_body(
                        body,
                        &f.params,
                        self_binding,
                        &call.arguments,
                        argument_states,
                        true,
                        f.r#async,
                        false,
                    );
                    self.record_call_source_return(call, result.source_return);
                    self.record_call_aggregate_return(call, result.aggregate_return);
                    JsCall::Local
                } else {
                    JsCall::Opaque
                }
            }
            Expression::ArrowFunctionExpression(a) => {
                let result = self.enter_inline_body(
                    &a.body,
                    &a.params,
                    None,
                    &call.arguments,
                    argument_states,
                    true,
                    a.r#async,
                    a.expression,
                );
                self.record_call_source_return(call, result.source_return);
                self.record_call_aggregate_return(call, result.aggregate_return);
                JsCall::Local
            }
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if let Some(info) =
                    resolve_callable(self.functions, &self.callable_env, name, call.span)
                {
                    let result = self.enter_function(info, &call.arguments, argument_states, true);
                    if let Some(producer) = result.producer {
                        self.stage_by_span.insert(call.span.start, producer);
                    }
                    self.record_call_source_return(call, result.source_return);
                    self.record_call_aggregate_return(call, result.aggregate_return);
                    JsCall::Local
                } else if !known(self)
                    && !self.apply_dependency_call(original_callee, call, argument_states)
                {
                    self.unresolved_call(call.span, name, Some(original_callee));
                    JsCall::Opaque
                } else {
                    JsCall::Modeled
                }
            }
            Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => {
                if self.follow_local_member_call(callee, call, argument_states) {
                    JsCall::Local
                } else if !known(self)
                    && !self.apply_dependency_call(original_callee, call, argument_states)
                {
                    self.unresolved_call(call.span, "member call", Some(original_callee));
                    JsCall::Opaque
                } else {
                    JsCall::Modeled
                }
            }
            _ => {
                if known(self) {
                    JsCall::Modeled
                } else {
                    self.unresolved_call(call.span, "expression call", Some(original_callee));
                    self.record_call_source_return(
                        call,
                        Some(SourceStringValue {
                            resource: None,
                            concatenation: true,
                        }),
                    );
                    JsCall::Opaque
                }
            }
        };

        // Callbacks passed as arguments may be invoked: follow conservatively.
        let direct = self.control_applications.len();
        let mut callbacks = 0;
        // A fulfillment handler receives the value its promise settles with.
        let then_receiver = match original_callee {
            Expression::StaticMemberExpression(member)
                if quiet_promise && member.property.name.as_str() == "then" =>
            {
                Some(&member.object)
            }
            _ => None,
        };
        let settled = then_receiver.and_then(|receiver| self.init_producer(receiver));
        let response = then_receiver.and_then(|receiver| self.response_kind(receiver));
        let message = self.message_handler(original_callee, call);
        for (index, arg) in call.arguments.iter().enumerate() {
            if let Some(expr) = arg.as_expression() {
                let handler = message
                    .as_ref()
                    .filter(|(handler_index, _, _)| *handler_index == index);
                let (settled, response) = match handler {
                    Some((_, stage, MessageHandler::Response)) => {
                        (Some(*stage), Some(ResponseKind::Message))
                    }
                    Some((_, stage, MessageHandler::Chunk | MessageHandler::File)) => {
                        (Some(*stage), None)
                    }
                    Some((_, _, MessageHandler::End)) => (None, None),
                    None => (settled.filter(|_| index == 0), response),
                };
                // A fulfillment handler runs, like the right side of `&&`,
                // once an established promise fulfills, and a response
                // handler once its request succeeds; other callbacks may or
                // may not be dispatched.
                let (kind, polarity) = if handler.is_some()
                    || index == 0
                        && then_receiver.is_some_and(|receiver| {
                            !promise_known_unfulfilled(receiver, self.bindings.throws_reject)
                        }) {
                    (effinterp_proto::ConditionKind::ShortCircuit, Some(true))
                } else {
                    (effinterp_proto::ConditionKind::Dispatch, None)
                };
                if let Some(stage) = settled
                    && !matches!(handler, Some((_, _, MessageHandler::File)))
                    && response.is_none()
                    && self.promise_handler_code_execution(expr, call.span, stage, kind, polarity)
                {
                    continue;
                }
                self.callback_seed = settled.and_then(|stage| {
                    let parameter =
                        usize::from(matches!(handler, Some((_, _, MessageHandler::File))));
                    let (body, param) = inline_callback_parameter(expr, parameter)?;
                    Some((body, param.to_string(), stage, response))
                });
                if let Some((_, _, MessageHandler::End)) = handler {
                    self.callback_captures = callback_body_start(expr).map(|body| {
                        let captures = self
                            .flow_vars
                            .iter()
                            .map(|(name, stage)| {
                                (name.clone(), *stage, self.response_vars.get(name).copied())
                            })
                            .collect();
                        (body, captures)
                    });
                }
                self.callback_producer = None;
                let followed = self.follow_callback_under(expr, kind, polarity);
                self.callback_seed = None;
                self.callback_captures = None;
                if let Some((_, stage, MessageHandler::Chunk)) = handler {
                    for name in chunk_accumulators(expr) {
                        if self.insert_flow_slot(name.clone()) {
                            self.response_vars.remove(&name);
                            self.flow_vars.insert(name, *stage);
                        }
                    }
                }
                // The chained promise settles with what the handler returns.
                if settled.is_some()
                    && !matches!(handler, Some((_, _, MessageHandler::File)))
                    && let Some(producer) = self.callback_producer.take()
                {
                    self.stage_by_span.insert(call.span.start, producer);
                }
                callbacks += usize::from(followed);
                if quiet_promise && !followed && callback_needs_resolution(expr) {
                    self.unresolved_call(call.span, "promise callback", None);
                }
            }
        }
        Reached {
            call: reached,
            direct,
            callbacks,
        }
    }

    /// The callback argument, its byte producer, and its role for a file
    /// read, HTTP response, or listener registered on that response.
    fn message_handler(
        &self,
        callee: &Expression<'a>,
        call: &CallExpression<'a>,
    ) -> Option<(usize, usize, MessageHandler)> {
        if let Some(target) = self.resolve_effect_callee(callee)
            && target.module == "fs"
            && target.function == "readFile"
            && matches!(call.arguments.len(), 2 | 3)
        {
            let stage = *self.stage_by_span.get(&call.span.start)?;
            return Some((call.arguments.len() - 1, stage, MessageHandler::File));
        }
        if let Some(target) = self.resolve_effect_callee(callee)
            && matches!(target.module.as_str(), "http" | "https")
            && target.function == "get"
        {
            let stage = *self.stage_by_span.get(&call.span.start)?;
            let index = call
                .arguments
                .len()
                .checked_sub(1)
                .filter(|index| *index > 0)?;
            return Some((index, stage, MessageHandler::Response));
        }
        let Expression::StaticMemberExpression(member) = callee else {
            return None;
        };
        let Expression::Identifier(receiver) = unparen(&member.object) else {
            return None;
        };
        if !matches!(member.property.name.as_str(), "on" | "once")
            || self.response_vars.get(receiver.name.as_str()) != Some(&ResponseKind::Message)
        {
            return None;
        }
        let stage = *self.flow_vars.get(receiver.name.as_str())?;
        let event = call.arguments.first().and_then(Argument::as_expression)?;
        let handler = match unparen(event) {
            Expression::StringLiteral(event) if event.value == "data" => MessageHandler::Chunk,
            Expression::StringLiteral(event) if event.value == "end" => MessageHandler::End,
            _ => return None,
        };
        Some((1, stage, handler))
    }

    /// `promise.then(eval)`: the settled value runs as code.
    fn promise_handler_code_execution(
        &mut self,
        handler: &Expression<'a>,
        call: Span,
        settled: usize,
        kind: effinterp_proto::ConditionKind,
        polarity: Option<bool>,
    ) -> bool {
        if !matches!(unparen(handler), Expression::Identifier(id) if id.name.as_str() == "eval")
            || !self.bindings.is_runtime_code(handler)
        {
            return false;
        }
        self.push_callback_condition(handler.span(), kind, polarity);
        let before = self.builder.effects_len();
        self.dynamic_code_execution(call, "eval");
        let after = self.builder.effects_len();
        self.builder.pop_condition();
        if let Some(stage) = self.new_stage(handler.span(), before, after) {
            self.stage_writer.add_edge(settled, stage, 0);
        }
        true
    }

    /// What a call establishes at its control-flow site. Only a modeled API's
    /// own occurrences or a directly entered body's guarantees count;
    /// callbacks run under the callee's control, so they can only add an
    /// unknown completion.
    fn call_control(
        &self,
        call: &CallExpression<'a>,
        reached: Reached,
        applied: Vec<SiteFacts>,
        modeled: std::ops::Range<usize>,
    ) -> SiteFacts {
        if self.saturated {
            return SiteFacts::unknown();
        }
        let (direct, callbacks) = applied.split_at(reached.direct.min(applied.len()));
        let direct_delete = resolve::resolve_callee(unparen(&call.callee), self.bindings)
            .is_some_and(|callee| callee.module == "fs" && callee.function == "unlinkSync");
        let mut facts = match (reached.call, direct) {
            (JsCall::Modeled, []) if direct_delete => {
                SiteFacts::known(self.builder.control_own_effects(modeled))
            }
            (JsCall::Modeled, []) => SiteFacts::known(Vec::new()),
            (JsCall::Local, [entered]) if modeled.is_empty() => entered.clone(),
            _ => SiteFacts::unknown(),
        };
        if callbacks.len() != reached.callbacks
            || callbacks
                .iter()
                .any(|callback| callback.exit.is_some() || callback.widen)
        {
            facts.exit = Some(ControlExit::Unknown);
        }
        if let Expression::Identifier(callee) = unparen(&call.callee)
            && callee.name.as_str() == "require"
            && !self.bindings.require_shadowed
        {
            // Loading a module runs its top level.
            facts.exit = match call.arguments.first() {
                Some(Argument::StringLiteral(source))
                    if model::is_node_builtin_module(source.value.as_str()) =>
                {
                    facts.exit
                }
                Some(Argument::StringLiteral(source)) => Some(ControlExit::Import {
                    module: source.value.to_string(),
                }),
                _ => Some(ControlExit::Unknown),
            };
        }
        if let Some(callee) = self.resolve_effect_callee(&call.callee)
            && callee.module == "process"
            && matches!(callee.function.as_str(), "exit" | "abort" | "reallyExit")
        {
            facts.returns = false;
            facts.exit = Some(ControlExit::Unknown);
        }
        facts
    }

    /// Compose a call through an exported function of a followed dependency
    /// (`helper.clean(dir)`, `clean(dir)` from `import { clean }`).
    fn apply_dependency_call(
        &mut self,
        callee: &Expression<'a>,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) -> bool {
        let Some(reference) = resolve::resolve_callee_reference(callee, self.bindings)
            .or_else(|| self.module_value_call(callee))
        else {
            return false;
        };
        if !crate::dependency_calls::is_path_specifier(&reference.module)
            || reference.function.is_empty()
            || reference.function.contains('.')
            || call
                .arguments
                .iter()
                .any(|argument| matches!(argument, Argument::SpreadElement(_)))
        {
            return false;
        }
        let arguments: Vec<_> = call
            .arguments
            .iter()
            .enumerate()
            .filter_map(|(index, argument)| {
                let resource =
                    self.argument_resource(argument.as_expression()?, argument_states.get(index));
                Some(crate::ValueArgument {
                    name: None,
                    index,
                    value: crate::SemanticValue::from(resource),
                })
            })
            .collect();
        let site = self.span_node(call.span);
        crate::dependency_calls::apply_dependency_call(
            self.builder,
            self.nest,
            &crate::dependency_calls::DependencyRequestKey {
                source_cwd: self.nest.current_source_cwd(),
                language: "js",
                specifier: reference.module,
            },
            &reference.function,
            &arguments,
            site,
            !self.bindings.environment_is_rewritten(),
        )
    }

    /// A call of a default import or a `require` result itself
    /// (`import wipe from './h.mjs'; wipe()`,
    /// `const wipe = require('./h.js'); wipe()`) calls the module's default
    /// export, which a summary also names for `module.exports = fn`. Calling
    /// an `import * as` namespace throws instead.
    fn module_value_call(&self, callee: &Expression<'a>) -> Option<ModuleCall> {
        let Expression::Identifier(id) = unparen(callee) else {
            return None;
        };
        if self.bindings.namespace_imports.contains(id.name.as_str()) {
            return None;
        }
        Some(ModuleCall {
            module: self.bindings.namespaces.get(id.name.as_str())?.clone(),
            function: "default".to_string(),
        })
    }

    fn follow_local_member_call(
        &mut self,
        callee: &Expression<'a>,
        call: &CallExpression<'a>,
        argument_states: &[SourceStringState],
    ) -> bool {
        let Expression::StaticMemberExpression(member) = callee else {
            return false;
        };
        let method = member.property.name.as_str();
        let function = match unparen(&member.object) {
            Expression::Identifier(owner) => self
                .functions
                .object_member(owner.name.as_str(), method, call.span)
                .filter(|(_, binding_scope)| {
                    self.member_binding_is_visible(owner.name.as_str(), *binding_scope)
                })
                .map(|(function, _)| function)
                .or_else(|| {
                    self.functions
                        .instance_member(owner.name.as_str(), method, call.span)
                        .filter(|(_, receiver_scope, class, class_scope)| {
                            self.member_binding_is_visible(owner.name.as_str(), *receiver_scope)
                                && self.member_binding_is_visible(class, *class_scope)
                        })
                        .map(|(function, _, _, _)| function)
                }),
            Expression::NewExpression(new) => match unparen(&new.callee) {
                Expression::Identifier(class) => self
                    .functions
                    .class_member(class.name.as_str(), method, call.span)
                    .filter(|(_, binding_scope)| {
                        self.member_binding_is_visible(class.name.as_str(), *binding_scope)
                    })
                    .map(|(function, _)| function),
                _ => None,
            },
            _ => None,
        };
        let Some(function) = function else {
            return false;
        };
        let result = self.enter_function(function, &call.arguments, argument_states, true);
        if let Some(producer) = result.producer {
            self.stage_by_span.insert(call.span.start, producer);
        }
        self.record_call_source_return(call, result.source_return);
        self.record_call_aggregate_return(call, result.aggregate_return);
        true
    }

    fn member_binding_is_visible(&self, name: &str, binding_scope: Span) -> bool {
        !self.active_bodies.iter().any(|active| {
            active.local_names.contains(name)
                && binding_scope.start < active.span.start
                && active.span.end < binding_scope.end
        })
    }

    fn record_call_source_return(
        &mut self,
        call: &CallExpression<'a>,
        source_return: Option<SourceStringValue>,
    ) {
        if let Some(source_return) = source_return {
            self.evaluated_source_strings
                .insert((call.span.start, call.span.end), source_return);
        }
    }

    fn record_call_aggregate_return(
        &mut self,
        call: &CallExpression<'a>,
        aggregate_return: AggregateAliasPaths,
    ) {
        if !aggregate_return.is_empty() {
            self.evaluated_aggregate_aliases
                .insert((call.span.start, call.span.end), aggregate_return);
        }
    }

    fn follow_callback(&mut self, expr: &Expression<'a>) -> bool {
        self.follow_callback_under(expr, effinterp_proto::ConditionKind::Dispatch, None)
    }

    /// An instance field initializer runs each time its class is
    /// instantiated, which may or may not happen, so it is walked where the
    /// class is defined under a dispatch condition. As with a branch that may
    /// be skipped, the state after it joins the state before it.
    fn instance_field_initializer(&mut self, value: &Expression<'a>) {
        let flow_entry = self.flow_entry();
        let entry = self.source_string_state();
        self.push_callback_condition(value.span(), effinterp_proto::ConditionKind::Dispatch, None);
        self.visit_expression(value);
        self.builder.pop_condition();
        let exit = self.source_string_state();
        self.join_source_string_states(exit, entry, value.span());
        self.flow_join(flow_entry);
    }

    /// Follow a callback under the condition that it is invoked: a generic
    /// dispatch, or a promise's fulfillment, which like the right side of
    /// `&&` runs only on success.
    fn follow_callback_under(
        &mut self,
        expr: &Expression<'a>,
        kind: effinterp_proto::ConditionKind,
        polarity: Option<bool>,
    ) -> bool {
        self.push_callback_condition(expr.span(), kind, polarity);
        let result = self.follow_guarded_callback(expr);
        self.builder.pop_condition();
        result
    }

    /// Enter the condition under which the callback at `span` is invoked.
    fn push_callback_condition(
        &mut self,
        span: Span,
        kind: effinterp_proto::ConditionKind,
        polarity: Option<bool>,
    ) {
        self.builder
            .push_condition(effinterp_proto::Condition::atom(
                effinterp_proto::ConditionAtom {
                    origin: effinterp_proto::ConditionOrigin {
                        source_digest: self.bindings.source_digest.clone(),
                        span: effinterp_proto::ByteSpan {
                            start: span.start,
                            end: span.end,
                        },
                        kind,
                        ordinal: span.start,
                        call_instance: None,
                    },
                    arm: 0,
                    arms: 2,
                    exhaustive: true,
                    polarity,
                    evidence: effinterp_proto::ConditionEvidence::Source {
                        path: None,
                        excerpt: None,
                    },
                },
            ));
    }

    fn follow_guarded_callback(&mut self, expr: &Expression<'a>) -> bool {
        match unparen(expr) {
            Expression::FunctionExpression(function) => {
                if function.generator {
                    true
                } else if let Some(body) = &function.body {
                    let self_binding = function.id.as_ref().map(|id| id.name.as_str());
                    self.callback_producer = self
                        .enter_inline_body(
                            body,
                            &function.params,
                            self_binding,
                            &[],
                            &[],
                            false,
                            function.r#async,
                            false,
                        )
                        .producer;
                    true
                } else {
                    false
                }
            }
            Expression::ArrowFunctionExpression(function) => {
                self.callback_producer = self
                    .enter_inline_body(
                        &function.body,
                        &function.params,
                        None,
                        &[],
                        &[],
                        false,
                        function.r#async,
                        function.expression,
                    )
                    .producer;
                true
            }
            Expression::Identifier(id) => {
                if let Some(function) = resolve_callable(
                    self.functions,
                    &self.callable_env,
                    id.name.as_str(),
                    id.span,
                ) {
                    let _ = self.enter_function(function, &[], &[], false);
                    true
                } else {
                    false
                }
            }
            Expression::ObjectExpression(object) => {
                let mut followed = false;
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            followed |= self.follow_callback(&property.value)
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            followed |= self.follow_callback(&spread.argument)
                        }
                    }
                }
                followed
            }
            Expression::ArrayExpression(array) => {
                let mut followed = false;
                for element in &array.elements {
                    if let Some(expr) = element.as_expression() {
                        followed |= self.follow_callback(expr);
                    }
                }
                followed
            }
            Expression::AwaitExpression(awaited) => self.follow_callback(&awaited.argument),
            _ => false,
        }
    }

    fn active_lexical_source_state(&self, body: Span) -> Option<SourceStringState> {
        let parent = self
            .active_bodies
            .iter()
            .rposition(|active| active.span.start < body.start && body.end < active.span.end)?;
        let mut state = self.source_string_state();
        for active in self.active_bodies[parent + 1..].iter().rev() {
            restore_source_string_state_names(
                self.nest.budget,
                &mut state,
                &active.enclosing_source_state,
                &active.local_names,
            );
        }
        Some(state)
    }

    fn active_lexical_process_runtime(&self, body: Span) -> Option<bool> {
        self.active_bodies
            .iter()
            .rfind(|active| active.span.start < body.start && body.end < active.span.end)
            .map(|active| active.process_runtime)
    }

    /// Enter a called local function: resolve the caller's arguments in the
    /// current environment, bind them positionally to the callee's parameters,
    /// and walk the body under that environment so a parameter identifier
    /// resolves to the argument the caller passed. Local bindings are restored
    /// afterwards; definitely executed calls retain writes to captured bindings.
    fn enter_function(
        &mut self,
        function: &collect::FnInfo<'a>,
        args: &[Argument<'a>],
        argument_states: &[SourceStringState],
        preserve_captured_writes: bool,
    ) -> BodyResult {
        if self.saturated || function.is_generator {
            return BodyResult::default();
        }
        let cwd_arg_exprs: Vec<ResourceExpr> =
            args.iter().map(|arg| self.arg_cwd_resource(arg)).collect();
        let mut new_cwd_env = self.cwd_consts.clone();
        new_cwd_env.extend(bind_positional(&function.params, &cwd_arg_exprs));
        let argument_source_env = self.source_env.clone();
        let argument_unbounded_source_env = self.unbounded_source_env.clone();
        let saved_source_state = self.source_string_state();
        let saved_process = self.process_runtime;
        // A nested function sees its lexical parent. A top-level callee sees
        // live module bindings rather than locals from an unrelated caller.
        let enclosing_source_state = self
            .active_lexical_source_state(function.body.span)
            .unwrap_or_else(|| SourceStringState {
                param_env: self.module_env.clone(),
                source_env: self.source_strings.clone(),
                unbounded_source_env: self.unbounded_source_strings.clone(),
                definitely_nullish_env: self.module_definitely_nullish_env.clone(),
                callable_env: self.module_callable_env.clone(),
                aggregate_aliases: self.module_aggregate_aliases.clone(),
            });
        if !self.charge_retained_state(
            &enclosing_source_state,
            object_literal_bytes(&self.object_literal_vars),
            function.body.span,
        ) {
            return BodyResult::default();
        }
        let saved_object_literal_vars = self.object_literal_vars.clone();
        let saved_cwd = std::mem::replace(&mut self.cwd_param_env, new_cwd_env);
        self.builder
            .control_enter(self.control_source, false, |graph| {
                control::build_function(
                    graph,
                    function.parameters,
                    function.body,
                    &self.bindings.readonly_writes,
                )
            });
        let enclosing_process_runtime = self
            .active_lexical_process_runtime(function.body.span)
            .unwrap_or_else(|| self.bindings.process_runtime());
        let mut new_env = enclosing_source_state.param_env.clone();
        let mut new_source_env = enclosing_source_state.source_env.clone();
        let mut new_unbounded_source_env = enclosing_source_state.unbounded_source_env.clone();
        let mut new_definitely_nullish_env = enclosing_source_state.definitely_nullish_env.clone();
        let mut new_callable_env = enclosing_source_state.callable_env.clone();
        let mut new_aggregate_aliases = enclosing_source_state.aggregate_aliases.clone();
        let mut local_names = function_local_binding_names(function.body);
        local_names.extend(function.param_bindings.iter().cloned());
        local_names.extend(function.self_binding.iter().cloned());
        let mut new_object_literal_vars = if self.active_bodies.iter().any(|active| {
            active.span.start < function.body.span.start && function.body.span.end < active.span.end
        }) {
            self.object_literal_vars.clone()
        } else {
            self.module_object_literal_vars.clone()
        };
        for name in &local_names {
            new_env.remove(name);
            new_callable_env.remove(name);
            new_callable_env.remove(&plus_coercion_binding_name(name));
            mark_unbounded_source_string(name, &mut new_source_env, &mut new_unbounded_source_env);
            new_definitely_nullish_env.remove(name);
            new_object_literal_vars.remove(name);
        }
        clear_aggregate_aliases(&mut new_aggregate_aliases, &local_names);
        self.param_env = new_env;
        self.source_env = new_source_env;
        self.unbounded_source_env = new_unbounded_source_env;
        self.definitely_nullish_env = new_definitely_nullish_env;
        self.callable_env = new_callable_env;
        self.aggregate_aliases = new_aggregate_aliases;
        self.object_literal_vars = new_object_literal_vars;
        let body_entry = self.source_string_state();
        self.source_string_write_names.push(HashSet::new());
        self.process_runtime = function.process_scope.unwrap_or(enclosing_process_runtime);
        self.function_depth += 1;
        for (index, parameter) in function.parameters.items.iter().enumerate() {
            let logical_argument = logical_call_argument(args, index);
            let argument = logical_argument.and_then(|(argument, _)| argument);
            let argument_evaluation_state =
                logical_argument.and_then(|(_, syntax_index)| argument_states.get(syntax_index));
            let default_source_env =
                argument_evaluation_state.map_or(&argument_source_env, |state| &state.source_env);
            let default_unbounded_source_env = argument_evaluation_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            let uses_default = parameter.initializer.is_some()
                && match logical_argument {
                    None => true,
                    Some((Some(argument), _)) => is_global_undefined(
                        argument,
                        default_source_env,
                        default_unbounded_source_env,
                    ),
                    Some((None, _)) => false,
                };
            if uses_default {
                self.visit_expression(parameter.initializer.as_deref().unwrap());
            }
            if let BindingPattern::BindingIdentifier(id) = &parameter.pattern {
                let name = id.name.as_str();
                let resource = if uses_default {
                    parameter
                        .initializer
                        .as_deref()
                        .and_then(|initializer| self.tracked_value(initializer))
                } else {
                    argument
                        .map(|argument| self.argument_resource(argument, argument_evaluation_state))
                };
                self.param_env.remove(name);
                if let Some(resource) = resource {
                    self.param_env.insert(name.to_string(), resource);
                }
            }
            let value = if uses_default {
                SourceBindingValue::Local(parameter.initializer.as_deref().unwrap())
            } else {
                match logical_argument {
                    None => SourceBindingValue::Missing,
                    Some((Some(argument), _)) => SourceBindingValue::Argument(argument),
                    Some((None, _)) => SourceBindingValue::Unbounded,
                }
            };
            let argument_state = (!uses_default)
                .then_some(argument_evaluation_state)
                .flatten();
            let argument_source_env =
                argument_state.map_or(&argument_source_env, |state| &state.source_env);
            let argument_unbounded_source_env = argument_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            self.visit_binding_pattern_defaults(&parameter.pattern, value);
            bind_source_string_pattern(
                &parameter.pattern,
                value,
                argument_source_env,
                argument_unbounded_source_env,
                &mut self.source_env,
                &mut self.unbounded_source_env,
                saved_process,
                self.process_runtime,
                &self.evaluated_source_strings,
            );
            self.bind_parameter_plus_coercion(
                &parameter.pattern,
                value,
                argument_state,
                &saved_source_state,
            );
            if !uses_default {
                self.bind_parameter_aggregate_alias(
                    &parameter.pattern,
                    argument,
                    argument_state,
                    &saved_source_state,
                );
            }
        }
        if let Some(rest) = &function.parameters.rest {
            self.bind_rest_parameter(
                &rest.rest.argument,
                function.parameters.items.len(),
                args,
                argument_states,
                &argument_source_env,
                &argument_unbounded_source_env,
                &saved_source_state.callable_env,
                &saved_source_state.aggregate_aliases,
                saved_process,
            );
        }
        self.function_depth -= 1;
        let mut result = self.enter_body(
            function.body,
            ActiveBody {
                span: function.body.span,
                enclosing_source_state,
                local_names: local_names.clone(),
                process_runtime: self.process_runtime,
            },
            function.expression_body,
        );
        self.leave_control_body(function.is_async);
        result.aggregate_return.retain(|_, targets| {
            targets.retain(|name| {
                !local_names
                    .iter()
                    .any(|local| binding_is_within(name, local))
            });
            !targets.is_empty()
        });
        if function.is_async {
            result.source_return = None;
            result.aggregate_return.clear();
        }
        let body_exit = self.source_string_state();
        let source_string_write_names = self.source_string_write_names.pop().unwrap();
        self.process_runtime = saved_process;
        self.cwd_param_env = saved_cwd;
        self.restore_source_string_state(saved_source_state);
        self.object_literal_vars = saved_object_literal_vars;
        self.propagate_captured_writes(
            &body_entry,
            &body_exit,
            &local_names,
            &source_string_write_names,
            preserve_captured_writes && !function.is_async,
            function.body.span,
        );
        result
    }

    /// Finish an entered body's control-flow frame and record what it
    /// guarantees to the call that entered it. An async body's continuation
    /// after its first await is not ordered with the caller.
    fn leave_control_body(&mut self, is_async: bool) {
        let finished = self.builder.control_leave();
        let application = match finished {
            Some(finished) if !is_async => SiteFacts::call(&finished.requirements, Some),
            _ => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
    }

    #[allow(clippy::too_many_arguments)]
    fn enter_inline_body<'b>(
        &mut self,
        body: &'b FunctionBody<'a>,
        params: &'b FormalParameters<'a>,
        self_binding: Option<&str>,
        args: &[Argument<'a>],
        argument_states: &[SourceStringState],
        preserve_captured_writes: bool,
        is_async: bool,
        expression_body: bool,
    ) -> BodyResult {
        let argument_source_env = self.source_env.clone();
        let argument_unbounded_source_env = self.unbounded_source_env.clone();
        let saved_process = self.process_runtime;
        let saved_source_state = self.source_string_state();
        if !self.charge_retained_state(&saved_source_state, 0, body.span) {
            return BodyResult::default();
        }
        let saved_object_literal_vars = self.object_literal_vars.clone();
        self.builder
            .control_enter(self.control_source, false, |graph| {
                control::build_function(graph, params, body, &self.bindings.readonly_writes)
            });
        let mut bound_names = HashSet::new();
        for parameter in &params.items {
            collect_binding_names(&parameter.pattern, &mut bound_names);
        }
        if let Some(rest) = &params.rest {
            collect_binding_names(&rest.rest.argument, &mut bound_names);
        }
        if let Some(name) = self_binding {
            bound_names.insert(name.to_string());
        }
        let mut local_names = function_local_binding_names(body);
        for name in &local_names {
            self.param_env.remove(name);
            self.callable_env.remove(name);
            self.callable_env.remove(&plus_coercion_binding_name(name));
            mark_unbounded_source_string(
                name,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            self.definitely_nullish_env.remove(name);
            self.object_literal_vars.remove(name);
        }
        for name in &bound_names {
            self.param_env.remove(name);
            self.callable_env.remove(name);
            self.callable_env.remove(&plus_coercion_binding_name(name));
            mark_unbounded_source_string(
                name,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            self.definitely_nullish_env.remove(name);
            self.object_literal_vars.remove(name);
        }
        let mut hidden_names = local_names.clone();
        hidden_names.extend(bound_names.iter().cloned());
        clear_aggregate_aliases(&mut self.aggregate_aliases, &hidden_names);
        let body_entry = self.source_string_state();
        self.source_string_write_names.push(HashSet::new());
        self.process_runtime = function_process_scope(body, params).unwrap_or(saved_process);
        self.function_depth += 1;
        for (index, parameter) in params.items.iter().enumerate() {
            let logical_argument = logical_call_argument(args, index);
            let argument = logical_argument.and_then(|(argument, _)| argument);
            let argument_evaluation_state =
                logical_argument.and_then(|(_, syntax_index)| argument_states.get(syntax_index));
            let default_source_env =
                argument_evaluation_state.map_or(&argument_source_env, |state| &state.source_env);
            let default_unbounded_source_env = argument_evaluation_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            let uses_default = parameter.initializer.is_some()
                && match logical_argument {
                    None => true,
                    Some((Some(argument), _)) => is_global_undefined(
                        argument,
                        default_source_env,
                        default_unbounded_source_env,
                    ),
                    Some((None, _)) => false,
                };
            if uses_default {
                self.visit_expression(parameter.initializer.as_deref().unwrap());
            }
            if let BindingPattern::BindingIdentifier(id) = &parameter.pattern {
                let name = id.name.as_str();
                let resource = if uses_default {
                    parameter
                        .initializer
                        .as_deref()
                        .and_then(|initializer| self.tracked_value(initializer))
                } else {
                    argument
                        .map(|argument| self.argument_resource(argument, argument_evaluation_state))
                };
                self.param_env.remove(name);
                if let Some(resource) = resource {
                    self.param_env.insert(name.to_string(), resource);
                }
            }
            let value = if uses_default {
                SourceBindingValue::Local(parameter.initializer.as_deref().unwrap())
            } else {
                match logical_argument {
                    None => SourceBindingValue::Missing,
                    Some((Some(argument), _)) => SourceBindingValue::Argument(argument),
                    Some((None, _)) => SourceBindingValue::Unbounded,
                }
            };
            let argument_state = (!uses_default)
                .then_some(argument_evaluation_state)
                .flatten();
            let argument_source_env =
                argument_state.map_or(&argument_source_env, |state| &state.source_env);
            let argument_unbounded_source_env = argument_state
                .map_or(&argument_unbounded_source_env, |state| {
                    &state.unbounded_source_env
                });
            self.visit_binding_pattern_defaults(&parameter.pattern, value);
            bind_source_string_pattern(
                &parameter.pattern,
                value,
                argument_source_env,
                argument_unbounded_source_env,
                &mut self.source_env,
                &mut self.unbounded_source_env,
                saved_process,
                self.process_runtime,
                &self.evaluated_source_strings,
            );
            self.bind_parameter_plus_coercion(
                &parameter.pattern,
                value,
                argument_state,
                &saved_source_state,
            );
            if !uses_default {
                self.bind_parameter_aggregate_alias(
                    &parameter.pattern,
                    argument,
                    argument_state,
                    &saved_source_state,
                );
            }
        }
        if let Some(rest) = &params.rest {
            self.bind_rest_parameter(
                &rest.rest.argument,
                params.items.len(),
                args,
                argument_states,
                &argument_source_env,
                &argument_unbounded_source_env,
                &saved_source_state.callable_env,
                &saved_source_state.aggregate_aliases,
                saved_process,
            );
        }
        self.function_depth -= 1;
        local_names.extend(bound_names);
        let mut result = self.enter_body(
            body,
            ActiveBody {
                span: body.span,
                enclosing_source_state: saved_source_state.clone(),
                local_names: local_names.clone(),
                process_runtime: self.process_runtime,
            },
            expression_body,
        );
        self.leave_control_body(is_async);
        result.aggregate_return.retain(|_, targets| {
            targets.retain(|name| {
                !local_names
                    .iter()
                    .any(|local| binding_is_within(name, local))
            });
            !targets.is_empty()
        });
        if is_async {
            result.source_return = None;
            result.aggregate_return.clear();
        }
        let body_exit = self.source_string_state();
        let source_string_write_names = self.source_string_write_names.pop().unwrap();
        self.restore_source_string_state(saved_source_state);
        self.object_literal_vars = saved_object_literal_vars;
        self.propagate_captured_writes(
            &body_entry,
            &body_exit,
            &local_names,
            &source_string_write_names,
            preserve_captured_writes && !is_async,
            body.span,
        );
        self.process_runtime = saved_process;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn bind_rest_parameter(
        &mut self,
        pattern: &BindingPattern<'a>,
        first_argument: usize,
        args: &[Argument<'a>],
        argument_states: &[SourceStringState],
        argument_source_env: &ParamEnv,
        argument_unbounded_source_env: &SourceStringNames,
        argument_callable_env: &CallableEnv,
        argument_aggregate_aliases: &AggregateAliases,
        argument_process_runtime: bool,
    ) {
        let BindingPattern::BindingIdentifier(identifier) = pattern else {
            return;
        };
        let prefix = format!("{}.", identifier.name.as_str());
        self.source_env.retain(|name, _| !name.starts_with(&prefix));
        self.unbounded_source_env
            .retain(|name| !name.starts_with(&prefix));
        self.callable_env.retain(|name, _| {
            !name.starts_with(&prefix) || !name.ends_with(PLUS_COERCION_BINDING_SUFFIX)
        });
        let Some(argument_count) = logical_call_argument_count(args) else {
            return;
        };
        for argument_index in first_argument..argument_count {
            let Some((argument, syntax_index)) = logical_call_argument(args, argument_index) else {
                continue;
            };
            let state = argument_states.get(syntax_index);
            let source_env = state.map_or(argument_source_env, |state| &state.source_env);
            let unbounded_source_env = state.map_or(argument_unbounded_source_env, |state| {
                &state.unbounded_source_env
            });
            let callable_env = state.map_or(argument_callable_env, |state| &state.callable_env);
            let aggregate_aliases =
                state.map_or(argument_aggregate_aliases, |state| &state.aggregate_aliases);
            let (resource, concatenation) = argument.map_or((None, false), |argument| {
                (
                    source_string_resource(
                        argument,
                        source_env,
                        unbounded_source_env,
                        argument_process_runtime,
                        &self.evaluated_source_strings,
                    ),
                    is_string_concatenation(argument, source_env, &self.evaluated_source_strings),
                )
            });
            let binding_name = format!(
                "{}{rest_index}",
                prefix,
                rest_index = argument_index - first_argument
            );
            set_source_string_binding(
                &binding_name,
                resource,
                concatenation,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            let binding = argument
                .and_then(|argument| {
                    self.plus_coercion_binding(argument, callable_env, aggregate_aliases)
                })
                .unwrap_or(CallableBinding::Unbounded);
            self.callable_env
                .insert(plus_coercion_binding_name(&binding_name), binding);
        }
    }

    fn propagate_captured_writes(
        &mut self,
        body_entry: &SourceStringState,
        body_exit: &SourceStringState,
        local_names: &HashSet<String>,
        candidates: &HashSet<String>,
        definitely_executed: bool,
        span: Span,
    ) {
        let captured_writes = changed_captured_bindings(
            self.nest.budget,
            body_entry,
            body_exit,
            local_names,
            candidates,
        );
        if captured_writes.is_empty() {
            return;
        }
        self.record_source_string_write_names(&captured_writes);
        if definitely_executed {
            self.restore_source_string_names(body_exit, &captured_writes);
        } else {
            let call_entry = self.source_string_state();
            self.restore_source_string_names(body_exit, &captured_writes);
            let call_exit = self.source_string_state();
            self.join_source_string_states(call_entry, call_exit, span);
        }
    }

    fn record_source_string_write_name(&mut self, name: &str) {
        if let Some(names) = self.source_string_write_names.last_mut() {
            names.insert(name.to_string());
        }
    }

    fn record_source_string_write_names(&mut self, changed: &HashSet<String>) {
        if let Some(names) = self.source_string_write_names.last_mut() {
            names.extend(changed.iter().cloned());
        }
    }

    fn track_source_string(
        &mut self,
        name: String,
        resource: Option<ResourceExpr>,
        concatenation: bool,
    ) {
        self.record_source_string_write_name(&name);
        match resource {
            Some(resource) => {
                self.source_env.insert(name.clone(), resource);
                self.unbounded_source_env.remove(&name);
            }
            None => {
                if concatenation {
                    // Preserve only the shape: the unbounded marker below keeps
                    // later sinks from treating these empty parts as a value.
                    self.source_env
                        .insert(name.clone(), ResourceExpr::Join { parts: Vec::new() });
                }
                mark_unbounded_source_string(
                    &name,
                    &mut self.source_env,
                    &mut self.unbounded_source_env,
                );
            }
        }
        self.sync_module_source_strings();
    }

    fn track_definitely_nullish(&mut self, name: &str, nullish: bool) {
        self.record_source_string_write_name(name);
        if nullish {
            self.definitely_nullish_env.insert(name.to_string());
        } else {
            self.definitely_nullish_env.remove(name);
        }
        self.sync_module_source_strings();
    }

    fn expression_is_definitely_nullish(&self, expression: &Expression<'a>) -> bool {
        match unparen(expression) {
            Expression::NullLiteral(_) => true,
            Expression::Identifier(id) => {
                self.definitely_nullish_env.contains(id.name.as_str())
                    || is_global_undefined(expression, &self.source_env, &self.unbounded_source_env)
            }
            Expression::UnaryExpression(unary) => unary.operator.as_str() == "void",
            Expression::SequenceExpression(sequence) => sequence
                .expressions
                .last()
                .is_some_and(|expression| self.expression_is_definitely_nullish(expression)),
            Expression::AssignmentExpression(assignment) if assignment.operator.is_assign() => {
                self.expression_is_definitely_nullish(&assignment.right)
            }
            Expression::ConditionalExpression(conditional) => {
                self.expression_is_definitely_nullish(&conditional.consequent)
                    && self.expression_is_definitely_nullish(&conditional.alternate)
            }
            Expression::AwaitExpression(awaited) => {
                self.expression_is_definitely_nullish(&awaited.argument)
            }
            _ => false,
        }
    }

    /// Reports the sub-expression that still runs when an optional link inside
    /// this chain short-circuits, or `None` when the whole chain runs.
    fn short_circuited_chain_base<'b>(
        &self,
        element: &'b ChainElement<'a>,
    ) -> Option<&'b Expression<'a>> {
        match element {
            ChainElement::CallExpression(call) => self.short_circuited_call_base(call),
            ChainElement::TSNonNullExpression(inner) => {
                self.short_circuited_link_base(&inner.expression)
            }
            _ => self.short_circuited_member_base(element.as_member_expression()?),
        }
    }

    fn short_circuited_link_base<'b>(
        &self,
        expression: &'b Expression<'a>,
    ) -> Option<&'b Expression<'a>> {
        match unparen(expression) {
            Expression::CallExpression(call) => self.short_circuited_call_base(call),
            Expression::TSNonNullExpression(inner) => {
                self.short_circuited_link_base(&inner.expression)
            }
            link => self.short_circuited_member_base(link.as_member_expression()?),
        }
    }

    fn short_circuited_member_base<'b>(
        &self,
        member: &'b MemberExpression<'a>,
    ) -> Option<&'b Expression<'a>> {
        // An earlier link stops the chain before this key is evaluated.
        self.short_circuited_link_base(member.object()).or_else(|| {
            (member.optional() && self.expression_is_definitely_nullish(member.object()))
                .then_some(member.object())
        })
    }

    fn short_circuited_call_base<'b>(
        &self,
        call: &'b CallExpression<'a>,
    ) -> Option<&'b Expression<'a>> {
        // A skipped optional call evaluates neither its arguments nor a target.
        self.short_circuited_link_base(&call.callee).or_else(|| {
            (call.optional && self.expression_is_definitely_nullish(&call.callee))
                .then_some(&call.callee)
        })
    }

    fn track_aggregate_source_strings(&mut self, name: &str, value: &Expression<'a>) {
        self.record_source_string_write_name(name);
        let names = binding_names_with_descendants(
            &HashSet::from([name.to_string()]),
            self.param_env
                .keys()
                .chain(self.source_env.keys())
                .chain(self.unbounded_source_env.iter()),
        );
        let descendants = names
            .into_iter()
            .filter(|candidate| candidate != name)
            .collect::<HashSet<_>>();
        self.mark_source_strings_unbounded(&descendants);

        let mut members = Vec::new();
        collect_aggregate_source_string_members(
            name,
            value,
            &self.source_env,
            &self.unbounded_source_env,
            self.process_runtime,
            &self.evaluated_source_strings,
            &mut members,
            0,
        );
        for (member, resource, concatenation) in members {
            set_source_string_binding(
                &member,
                resource,
                concatenation,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
        }
        self.sync_module_source_strings();
    }

    fn track_callable_declarator(
        &mut self,
        name: &str,
        init: &Expression<'a>,
        initialized_at: u32,
    ) {
        self.record_source_string_write_name(name);
        if matches!(
            unparen(init),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            self.callable_env.insert(
                name.to_string(),
                CallableBinding::Declarator(initialized_at),
            );
        } else {
            self.callable_env
                .insert(name.to_string(), CallableBinding::Unbounded);
        }
        self.sync_module_source_strings();
    }

    fn track_callable_assignment(
        &mut self,
        name: &str,
        value: &Expression<'a>,
        assignment_span: u32,
    ) {
        self.record_source_string_write_name(name);
        let binding = if matches!(
            unparen(value),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) && collect::resolve_assignment(self.functions, name, assignment_span)
            .is_some()
        {
            CallableBinding::Assigned(assignment_span)
        } else {
            CallableBinding::Unbounded
        };
        self.callable_env.insert(name.to_string(), binding);
        self.sync_module_source_strings();
    }

    fn mark_callable_binding_unbounded(&mut self, name: String) {
        self.record_source_string_write_name(&name);
        if !name.ends_with(PLUS_COERCION_BINDING_SUFFIX) {
            self.callable_env.insert(
                plus_coercion_binding_name(&name),
                CallableBinding::Unbounded,
            );
        }
        self.callable_env.insert(name, CallableBinding::Unbounded);
        self.sync_module_source_strings();
    }

    fn mark_callable_bindings_unbounded(&mut self, names: &HashSet<String>) {
        if names.is_empty() {
            return;
        }
        self.record_source_string_write_names(names);
        for name in names {
            if !name.ends_with(PLUS_COERCION_BINDING_SUFFIX) {
                self.callable_env
                    .insert(plus_coercion_binding_name(name), CallableBinding::Unbounded);
            }
            self.callable_env
                .insert(name.clone(), CallableBinding::Unbounded);
        }
        self.sync_module_source_strings();
    }

    fn mark_source_strings_unbounded(&mut self, names: &HashSet<String>) {
        if names.is_empty() {
            return;
        }
        self.record_source_string_write_names(names);
        for name in names {
            self.param_env.remove(name);
            mark_unbounded_source_string(
                name,
                &mut self.source_env,
                &mut self.unbounded_source_env,
            );
            self.definitely_nullish_env.remove(name);
        }
        self.sync_module_source_strings();
    }

    fn mark_source_bindings_unbounded(&mut self, names: &HashSet<String>) {
        let names = binding_names_with_descendants(
            names,
            self.param_env
                .keys()
                .chain(self.source_env.keys())
                .chain(self.unbounded_source_env.iter()),
        );
        clear_aggregate_aliases(&mut self.aggregate_aliases, &names);
        self.mark_source_strings_unbounded(&names);
    }

    fn mark_source_binding_writes_unbounded(&mut self, names: &HashSet<String>) {
        let names = aggregate_alias_binding_names(self.nest.budget, &self.aggregate_aliases, names);
        let aggregate_names: HashSet<String> = names
            .iter()
            .filter_map(|name| name.strip_suffix(".length").map(str::to_string))
            .collect();
        let mut names = names;
        names.extend(aggregate_names);
        // Replacing Promise also replaces the Promise.resolve passthrough
        // consulted by transparent builtin lowering.
        if names.contains("Promise") {
            names.insert("Promise.resolve".to_string());
        }
        let descendants: HashSet<String> = self
            .param_env
            .keys()
            .chain(self.source_env.keys())
            .chain(self.unbounded_source_env.iter())
            .filter(|candidate| {
                names.iter().any(|name| {
                    candidate
                        .strip_prefix(name)
                        .is_some_and(|suffix| suffix.starts_with('.'))
                })
            })
            .cloned()
            .collect();
        names.extend(descendants);
        self.mark_source_strings_unbounded(&names);
    }

    fn for_statement_left_lexical_names(
        &self,
        left: &oxc_ast::ast::ForStatementLeft<'a>,
    ) -> HashSet<String> {
        let mut names = HashSet::new();
        if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) = left
            && declaration.kind != VariableDeclarationKind::Var
        {
            for declarator in &declaration.declarations {
                collect_binding_names(&declarator.id, &mut names);
            }
        }
        names
    }

    fn for_statement_left_assignment_names(
        &self,
        left: &oxc_ast::ast::ForStatementLeft<'a>,
    ) -> HashSet<String> {
        let mut bindings = AssignmentTargetBindings::default();
        if let Some(target) = left.as_assignment_target() {
            bindings.visit_assignment_target(target);
        }
        bindings.names
    }

    fn sync_module_object_literals(&mut self) {
        if self.function_depth == 0 {
            self.module_object_literal_vars
                .clone_from(&self.object_literal_vars);
        }
    }

    /// The resource a variable refers to after `= init`, or None to drop any
    /// stale tracking for it: the return of a call into a local function whose
    /// return resolves, otherwise `init` lowered as a path when that resolves.
    fn tracked_value(&self, init: &Expression<'a>) -> Option<ResourceExpr> {
        if let Expression::CallExpression(call) = unparen(init)
            && let Expression::Identifier(id) = unparen(&call.callee)
            && let Some(info) = resolve_callable(
                self.functions,
                &self.callable_env,
                id.name.as_str(),
                call.span,
            )
        {
            return self.call_return_resource(info, &call.arguments);
        }
        let resolved = resolve::fs_resource(
            init,
            self.runtime_cwd_resource.clone(),
            self.source_cwd,
            &self.param_env,
            self.bindings,
        );
        (!matches!(resolved, ResourceExpr::Unresolved { .. })).then_some(resolved)
    }

    fn tracked_cwd_value(&self, init: &Expression<'a>) -> Option<ResourceExpr> {
        if let Expression::CallExpression(call) = unparen(init)
            && let Expression::Identifier(id) = unparen(&call.callee)
            && let Some(info) = resolve_callable(
                self.functions,
                &self.callable_env,
                id.name.as_str(),
                call.span,
            )
        {
            return self.call_return_cwd_resource(info, &call.arguments);
        }
        let resolved = resolve::fs_resource(
            init,
            None,
            self.source_cwd,
            &self.cwd_param_env,
            self.bindings,
        );
        (!matches!(resolved, ResourceExpr::Unresolved { .. })).then_some(resolved)
    }

    /// The resource a call into a local function returns: resolve the caller's
    /// arguments in the current scope, bind them to the callee's parameters
    /// (over the live module bindings), and infer the callee's return under that
    /// environment. None when the return is not a single resolvable resource.
    fn call_return_resource(
        &self,
        info: &collect::FnInfo<'a>,
        args: &[Argument<'a>],
    ) -> Option<ResourceExpr> {
        if info.is_async || info.is_generator {
            return None;
        }
        let arg_exprs: Vec<ResourceExpr> = (0..info.params.len())
            .map(|index| {
                logical_call_argument(args, index)
                    .and_then(|(argument, _)| argument)
                    .map_or(unresolved_resource("filesystem"), |argument| {
                        self.argument_resource(argument, None)
                    })
            })
            .collect();
        let mut env = self.module_env.clone();
        for name in &info.param_bindings {
            env.remove(name);
        }
        env.extend(bind_positional(&info.params, &arg_exprs));
        resolve::infer_returns(
            &info.body.statements,
            self.runtime_cwd_resource.clone(),
            self.source_cwd,
            &env,
            self.bindings,
        )
    }

    fn call_return_cwd_resource(
        &self,
        info: &collect::FnInfo<'a>,
        args: &[Argument<'a>],
    ) -> Option<ResourceExpr> {
        if info.is_async || info.is_generator {
            return None;
        }
        let arg_exprs: Vec<ResourceExpr> = (0..info.params.len())
            .map(|index| {
                logical_call_argument(args, index)
                    .and_then(|(argument, _)| argument)
                    .map_or(unresolved_resource("filesystem"), |argument| {
                        resolve::fs_resource(
                            argument,
                            None,
                            self.source_cwd,
                            &self.cwd_param_env,
                            self.bindings,
                        )
                    })
            })
            .collect();
        let mut env = self.cwd_consts.clone();
        for name in &info.param_bindings {
            env.remove(name);
        }
        env.extend(bind_positional(&info.params, &arg_exprs));
        resolve::infer_returns(
            &info.body.statements,
            None,
            self.source_cwd,
            &env,
            self.bindings,
        )
    }

    fn argument_resource(
        &self,
        argument: &Expression<'a>,
        state: Option<&SourceStringState>,
    ) -> ResourceExpr {
        resolve::fs_resource(
            argument,
            self.runtime_cwd_resource.clone(),
            self.source_cwd,
            state.map_or(&self.param_env, |state| &state.param_env),
            self.bindings,
        )
    }

    fn arg_cwd_resource(&self, arg: &Argument<'a>) -> ResourceExpr {
        match argument_expr(arg) {
            Some(expr) => resolve::fs_resource(
                expr,
                None,
                self.source_cwd,
                &self.cwd_param_env,
                self.bindings,
            ),
            None => unresolved_resource("filesystem"),
        }
    }

    /// Analyze the statements of a reachable function body, guarding against
    /// call cycles by body span. Generic over the borrow so a local function's
    /// stored `'a` body and an inline IIFE/callback body both work.
    fn enter_body<'b>(
        &mut self,
        body: &'b oxc_ast::ast::FunctionBody<'a>,
        active_body: ActiveBody,
        expression_body: bool,
    ) -> BodyResult {
        if self.saturated || !self.visiting.insert(body.span.start) {
            return BodyResult::default();
        }
        let previous_call = self
            .builder
            .enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(&self.bindings.source_digest, self.condition_site),
            ));
        self.entered_callable_body = true;
        // A nested body is a separate scope: the caller's tracked producers are
        // not visible under the callee's parameter names (a same-named parameter
        // shadows them), so def-use tracking starts empty and is restored after.
        let saved_flow = std::mem::take(&mut self.flow_vars);
        let saved_slots = std::mem::take(&mut self.flow_slots);
        let saved_shapes = std::mem::take(&mut self.flow_shapes);
        let saved_responses = std::mem::take(&mut self.response_vars);
        // A compiled local stays callable from the nested body.
        let saved_compiled = self.compiled_vars.clone();
        if let Some((_, name, stage, response)) = self
            .callback_seed
            .take_if(|(seeded, _, _, _)| *seeded == body.span.start)
            && self.insert_flow_slot(name.clone())
        {
            if let Some(response) = response {
                self.response_vars.insert(name.clone(), response);
            }
            self.flow_vars.insert(name, stage);
        }
        if let Some((_, captures)) = self
            .callback_captures
            .take_if(|(seeded, _)| *seeded == body.span.start)
        {
            // Names the callback binds itself shadow the enclosing ones.
            for (name, stage, response) in captures {
                let root = name.split('.').next().unwrap_or(&name);
                if active_body.local_names.contains(root) || !self.insert_flow_slot(name.clone()) {
                    continue;
                }
                if let Some(response) = response {
                    self.response_vars.insert(name.clone(), response);
                }
                self.flow_vars.insert(name, stage);
            }
        }
        self.function_depth += 1;
        self.active_bodies.push(active_body);
        let caller_blocks = std::mem::take(&mut self.block_bindings);
        self.block_bindings = caller_blocks
            .iter()
            .filter(|(block, _)| block.start <= body.span.start && body.span.end <= block.end)
            .cloned()
            .collect();
        self.return_producers.push(Vec::new());
        self.return_source_states.push(Vec::new());
        self.return_source_values.push(Vec::new());
        self.return_aggregate_aliases
            .push(AggregateAliasPaths::new());
        let mut continues = true;
        for stmt in &body.statements {
            self.visit_statement(stmt);
            if statement_stops_sequential_execution(stmt) {
                continues = false;
                break;
            }
        }
        if continues
            && expression_body
            && let [Statement::ExpressionStatement(statement)] = body.statements.as_slice()
        {
            let source_value = SourceStringValue {
                resource: source_string_resource(
                    &statement.expression,
                    &self.source_env,
                    &self.unbounded_source_env,
                    self.process_runtime,
                    &self.evaluated_source_strings,
                ),
                concatenation: self.is_string_concatenation(&statement.expression),
            };
            self.return_source_values
                .last_mut()
                .unwrap()
                .push(source_value);
            let aggregate_aliases = expression_aggregate_alias_paths(
                self.nest.budget,
                &statement.expression,
                &self.aggregate_aliases,
                &self.evaluated_aggregate_aliases,
            );
            extend_aggregate_alias_paths(
                self.return_aggregate_aliases.last_mut().unwrap(),
                "",
                aggregate_aliases,
            );
            self.retain_return_source_state(body.span);
            let producer = self.init_producer(&statement.expression);
            self.return_producers.last_mut().unwrap().push(producer);
            continues = false;
        }
        let returns = self.return_producers.pop().unwrap();
        let mut source_exits = self.return_source_states.pop().unwrap();
        let mut source_values = self.return_source_values.pop().unwrap();
        let aggregate_return = self.return_aggregate_aliases.pop().unwrap();
        if continues {
            source_exits.push(self.source_string_state());
            source_values.push(SourceStringValue {
                resource: None,
                concatenation: false,
            });
        }
        if let Some(first) = source_exits.first().cloned() {
            self.restore_source_string_state(first);
            for exit in source_exits.into_iter().skip(1) {
                let joined = self.source_string_state();
                self.join_source_string_states(joined, exit, body.span);
            }
        }
        if self.flow_slots_saturated {
            self.flow_vars.clear();
            self.flow_slots.clear();
            self.flow_shapes.clear();
        } else {
            self.flow_vars = saved_flow;
            self.flow_slots = saved_slots;
            self.flow_shapes = saved_shapes;
        }
        self.response_vars = saved_responses;
        self.compiled_vars = saved_compiled;
        self.active_bodies.pop();
        self.block_bindings = caller_blocks;
        self.function_depth -= 1;
        self.visiting.remove(&body.span.start);
        let producer = returns
            .first()
            .copied()
            .flatten()
            .filter(|first| returns.iter().all(|producer| *producer == Some(*first)));
        let source_return = source_values.first().cloned().and_then(|first| {
            if source_values.iter().all(|value| value == &first) {
                Some(first)
            } else if source_values.iter().any(|value| value.concatenation) {
                Some(SourceStringValue {
                    resource: None,
                    concatenation: true,
                })
            } else {
                None
            }
        });
        self.builder.leave_condition_call(previous_call);
        BodyResult {
            producer,
            source_return,
            aggregate_return,
        }
    }

    /// A call we cannot resolve to a summary or trusted model. It could reach
    /// any domain, so opacity is declared across all of them.
    fn unresolved_call(&mut self, span: Span, name: &str, callee: Option<&Expression<'a>>) {
        let node = self.span_node(span);
        let callee = callee
            .filter(|callee| {
                !model::inert_base_name(callee).is_some_and(|name| {
                    self.active_bodies
                        .last()
                        .is_some_and(|body| body.local_names.contains(name))
                })
            })
            .and_then(|callee| resolve::resolve_callee_reference(callee, self.bindings))
            .map(|callee| CalleeReference {
                module: callee.module,
                symbol: callee.function,
            });
        self.builder.global_opacity(CoverageLevel::Partial);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call to unresolved {name}")),
        });
    }

    /// Enter one Visit frame; false once the walk-depth bound is hit.
    fn enter_walk(&mut self) -> bool {
        if self.saturated {
            return false;
        }
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.saturated = true;
            for domain in JS_DOMAINS {
                self.builder
                    .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
            }
            self.builder.boundary(Boundary {
                reason: BoundaryReason::PARTIAL_ANALYSIS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: self.scope.as_slice().to_vec(),
                limit: Some("max_walk_depth".to_string()),
                detail: Some("js walk depth bound reached".to_string()),
            });
            return false;
        }
        self.walk_depth += 1;
        true
    }

    /// Count one node against the frontend cap and the whole-analysis step
    /// budget; false once either is saturated.
    fn charge(&mut self, span: Span) -> bool {
        self.observe_state_budget(span);
        if self.saturated {
            return false;
        }
        if !crate::nest::charge_analysis_steps(
            self.builder,
            self.nest.budget,
            1,
            Some((span.start, span.end)),
        ) {
            self.saturated = true;
            return false;
        }
        self.nodes += 1;
        if self.nodes > self.max_nodes {
            self.saturated = true;
            for domain in JS_DOMAINS {
                self.builder
                    .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
            }
            self.builder.boundary(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: self.scope.as_slice().to_vec(),
                limit: Some("max_js_nodes".to_string()),
                detail: None,
            });
            return false;
        }
        true
    }

    fn span_node(&mut self, span: Span) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: span.start,
                end: span.end,
            },
            self.scope.as_slice(),
        )
    }

    fn sink_string_concatenation(
        &self,
        expr: &Expression<'a>,
        domain: &str,
        state: Option<&SourceStringState>,
    ) -> Option<ResourceExpr> {
        if !self.is_string_concatenation_at(expr, state) {
            return None;
        }
        let source_env = state.map_or(&self.source_env, |state| &state.source_env);
        let unbounded_source_env = state.map_or(&self.unbounded_source_env, |state| {
            &state.unbounded_source_env
        });
        let ResourceExpr::Join { mut parts } = source_string_resource(
            expr,
            source_env,
            unbounded_source_env,
            self.process_runtime,
            &self.evaluated_source_strings,
        )?
        else {
            return None;
        };
        parts.retain(|part| !matches!(part, ResourceExpr::Literal { value } if value.is_empty()));
        let resource =
            crate::value::sink_typed_concat(parts, domain, self.runtime_cwd_resource.clone());
        let resource = match effinterp_proto::normalize_resource(
            resource,
            effinterp_proto::PathPlatform::Posix,
        ) {
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            }
            | ResourceExpr::Literal { value: path } => {
                crate::paths::resolve_fs_path_with_cwd(&path, self.runtime_cwd_resource.clone())
            }
            resource => resource,
        };
        (!matches!(resource, ResourceExpr::Unresolved { .. })).then_some(resource)
    }

    fn is_string_concatenation(&self, expr: &Expression<'a>) -> bool {
        is_string_concatenation(expr, &self.source_env, &self.evaluated_source_strings)
    }

    fn is_string_concatenation_at(
        &self,
        expr: &Expression<'a>,
        state: Option<&SourceStringState>,
    ) -> bool {
        is_string_concatenation(
            expr,
            state.map_or(&self.source_env, |state| &state.source_env),
            &self.evaluated_source_strings,
        )
    }

    fn logical_call_argument_has_concatenation(
        &self,
        arguments: &[Argument<'a>],
        wanted: usize,
        argument_states: &[SourceStringState],
    ) -> bool {
        logical_call_argument_at_matches(arguments, wanted, |syntax_index, expression| {
            self.is_string_concatenation_at(expression, argument_states.get(syntax_index))
        })
    }

    fn unmodeled_dynamic(&mut self, span: Span, detail: &str) {
        let node = self.span_node(span);
        for domain in JS_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JS_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
    fn opaque(&mut self, span: Span, detail: &str) {
        self.opaque_needing(span, detail, Vec::new());
    }

    /// An opaque boundary that names the environment variables whose host
    /// values would resolve it, so the host is asked for them.
    fn opaque_needing(&mut self, span: Span, detail: &str, variables: Vec<String>) {
        let mut variables = variables
            .into_iter()
            .map(|name| ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { name },
            })
            .collect::<Vec<_>>();
        let affected_resource = match variables.len() {
            0 => None,
            1 => variables.pop(),
            _ => Some(ResourceExpr::Union {
                alternatives: variables,
            }),
        };
        let node = self.span_node(span);
        for domain in JS_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC_CODE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource,
            callee: None,
            domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }

    // --- Intra-function dataflow (def-use) ---
    //
    // A call that produces an effect is a flow stage; the value it returns is
    // its `Value` port. `const d = <producer>` remembers the stage, and a later
    // use of `d` as (or within) an argument to another producing call emits a
    // `data_flow` edge from the producer's `Value` to the consumer's `Arg(n)`.
    // Conservative and structural: local variables within this walk only.

    /// The producers flowing into the code arguments of a compile expression.
    fn code_producers(&self, code: &[Argument<'a>]) -> Vec<usize> {
        let mut producers = Vec::new();
        for argument in code.iter().filter_map(Argument::as_expression) {
            self.collect_producers(argument, &mut producers);
        }
        producers
    }

    /// The code producers of a compiled local a call names, unless a body
    /// entered since its binding declares the same name.
    fn compiled_local(&self, callee: &Expression<'a>) -> Option<Vec<usize>> {
        let Expression::Identifier(id) = unparen(callee) else {
            return None;
        };
        let (depth, producers) = self.compiled_vars.get(id.name.as_str())?;
        let shadowed = self
            .active_bodies
            .iter()
            .skip(*depth)
            .any(|body| body.local_names.contains(id.name.as_str()));
        (!shadowed).then(|| producers.clone())
    }

    /// Wire def-use edges into `consumer` from each argument that carries a
    /// tracked variable's value or a producer call nested directly in it.
    fn wire_arguments(&mut self, arguments: &[Argument<'a>], consumer: usize) {
        for (idx, arg) in arguments.iter().enumerate() {
            if let Some(expr) = arg.as_expression() {
                let mut producers = Vec::new();
                self.collect_producers(expr, &mut producers);
                for producer in producers {
                    self.stage_writer.add_edge(producer, consumer, idx as u32);
                }
            }
        }
    }

    /// Collect the producer stages an argument expression references: tracked
    /// variable identifiers and producer calls nested in it (through object
    /// property values, array elements, and template holes). Deliberately
    /// shallow — no descent into nested call arguments or member chains.
    fn collect_producers(&self, expr: &Expression<'a>, out: &mut Vec<usize>) {
        match unparen(expr) {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                let prefix = format!("{name}.");
                for stage in self
                    .flow_vars
                    .iter()
                    .filter(|(key, _)| *key == name || key.starts_with(&prefix))
                    .map(|(_, stage)| *stage)
                {
                    push_unique(out, stage);
                }
            }
            Expression::StaticMemberExpression(member) => {
                if let Some(&stage) = self.stage_by_span.get(&member.span.start) {
                    push_unique(out, stage);
                } else if let Some(name) = expression_flow_key(expr)
                    && let Some(&stage) = self.flow_vars.get(&name)
                {
                    push_unique(out, stage);
                }
            }
            Expression::ComputedMemberExpression(member) => {
                if let Some(&stage) = self.stage_by_span.get(&member.span.start) {
                    push_unique(out, stage);
                } else if let Some(name) = expression_flow_key(expr)
                    && let Some(&stage) = self.flow_vars.get(&name)
                {
                    push_unique(out, stage);
                }
            }
            Expression::AwaitExpression(awaited) => self.collect_producers(&awaited.argument, out),
            Expression::CallExpression(_) => {
                if let Some(stage) = self.init_producer(expr) {
                    push_unique(out, stage);
                }
            }
            Expression::ObjectExpression(o) => {
                for p in &o.properties {
                    match p {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) => {
                            self.collect_producers(&prop.value, out);
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            self.collect_producers(&spread.argument, out);
                        }
                    }
                }
            }
            Expression::ArrayExpression(a) => {
                for el in &a.elements {
                    match el {
                        oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                            self.collect_producers(&spread.argument, out)
                        }
                        _ => {
                            if let Some(e) = el.as_expression() {
                                self.collect_producers(e, out);
                            }
                        }
                    }
                }
            }
            Expression::TemplateLiteral(t) => {
                for e in &t.expressions {
                    self.collect_producers(e, out);
                }
            }
            _ => {}
        }
    }
}

/// Push `value` into `out` if not already present (small sets, linear scan).
fn push_unique(out: &mut Vec<usize>, value: usize) {
    if !out.contains(&value) {
        out.push(value);
    }
}

/// The expression carried by a non-spread argument.
fn argument_expr<'a, 'b>(arg: &'b Argument<'a>) -> Option<&'b Expression<'a>> {
    arg.as_expression()
}

fn string_conversion_argument<'a, 'b>(expr: &'b Expression<'a>) -> Option<&'b Expression<'a>> {
    let Expression::CallExpression(call) = unparen(expr) else {
        return None;
    };
    let Expression::Identifier(callee) = unparen(&call.callee) else {
        return None;
    };
    if callee.name != "String" {
        return None;
    }
    logical_call_argument(&call.arguments, 0).and_then(|(argument, _)| argument)
}

/// Resolve a call's logical argument position across statically sized array spreads.
/// The syntax index selects the source-string state captured after that argument.
fn logical_call_argument<'a, 'b>(
    arguments: &'b [Argument<'a>],
    wanted: usize,
) -> Option<(Option<&'b Expression<'a>>, usize)> {
    let mut logical_index = 0;
    for (syntax_index, argument) in arguments.iter().enumerate() {
        match argument {
            Argument::SpreadElement(spread) => {
                let Some(len) = array_literal_len(&spread.argument) else {
                    return (logical_index <= wanted).then_some((None, syntax_index));
                };
                if wanted < logical_index + len {
                    return Some((
                        array_element(&spread.argument, wanted - logical_index),
                        syntax_index,
                    ));
                }
                logical_index += len;
            }
            _ => {
                if logical_index == wanted {
                    return Some((argument_expr(argument), syntax_index));
                }
                logical_index += 1;
            }
        }
    }
    None
}

fn logical_call_argument_bindings(arguments: &[Argument<'_>], wanted: usize) -> HashSet<String> {
    let mut bindings = HashSet::new();
    let mut min_index = 0;
    let mut max_index = Some(0);
    for argument in arguments {
        match argument {
            Argument::SpreadElement(spread) => {
                collect_array_element_bindings_at_position(
                    &spread.argument,
                    wanted,
                    &mut min_index,
                    &mut max_index,
                    &mut bindings,
                );
            }
            _ => {
                if position_can_match(wanted, min_index, max_index)
                    && let Some(name) = argument_expr(argument).and_then(expression_flow_key)
                {
                    bindings.insert(name);
                }
                min_index += 1;
                max_index = max_index.map(|index| index + 1);
            }
        }
    }
    bindings
}

fn collect_array_element_bindings_at_position(
    expr: &Expression<'_>,
    wanted: usize,
    min_index: &mut usize,
    max_index: &mut Option<usize>,
    bindings: &mut HashSet<String>,
) {
    let array = match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            collect_array_element_bindings_at_position(
                &awaited.argument,
                wanted,
                min_index,
                max_index,
                bindings,
            );
            return;
        }
        Expression::ArrayExpression(array) => array,
        _ => {
            if *min_index <= wanted
                && let Some(name) = expression_flow_key(expr)
            {
                let max_start = max_index.unwrap_or(wanted).min(wanted);
                for start in *min_index..=max_start {
                    bindings.insert(format!("{name}.{}", wanted - start));
                }
            }
            *max_index = None;
            return;
        }
    };
    for element in &array.elements {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                collect_array_element_bindings_at_position(
                    &spread.argument,
                    wanted,
                    min_index,
                    max_index,
                    bindings,
                );
            }
            ArrayExpressionElement::Elision(_) => {
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
            element => {
                if position_can_match(wanted, *min_index, *max_index)
                    && let Some(name) = element.as_expression().and_then(expression_flow_key)
                {
                    bindings.insert(name);
                }
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
        }
    }
}

fn logical_call_argument_count(arguments: &[Argument<'_>]) -> Option<usize> {
    arguments.iter().try_fold(0, |count, argument| {
        Some(match argument {
            Argument::SpreadElement(spread) => count + array_literal_len(&spread.argument)?,
            _ => count + 1,
        })
    })
}

fn logical_call_argument_at_matches<'a>(
    arguments: &[Argument<'a>],
    wanted: usize,
    mut predicate: impl FnMut(usize, &Expression<'a>) -> bool,
) -> bool {
    let mut min_index = 0;
    let mut max_index = Some(0);
    for (syntax_index, argument) in arguments.iter().enumerate() {
        match argument {
            Argument::SpreadElement(spread) => {
                if array_elements_at_position_match(
                    &spread.argument,
                    wanted,
                    syntax_index,
                    &mut min_index,
                    &mut max_index,
                    &mut predicate,
                ) {
                    return true;
                }
            }
            _ => {
                if position_can_match(wanted, min_index, max_index)
                    && argument_expr(argument).is_some_and(|expr| predicate(syntax_index, expr))
                {
                    return true;
                }
                min_index += 1;
                max_index = max_index.map(|index| index + 1);
            }
        }
    }
    false
}

fn array_elements_at_position_match<'a>(
    expr: &Expression<'a>,
    wanted: usize,
    syntax_index: usize,
    min_index: &mut usize,
    max_index: &mut Option<usize>,
    predicate: &mut impl FnMut(usize, &Expression<'a>) -> bool,
) -> bool {
    let array = match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            return array_elements_at_position_match(
                &awaited.argument,
                wanted,
                syntax_index,
                min_index,
                max_index,
                predicate,
            );
        }
        Expression::ArrayExpression(array) => array,
        _ => {
            *max_index = None;
            return false;
        }
    };
    for element in &array.elements {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                if array_elements_at_position_match(
                    &spread.argument,
                    wanted,
                    syntax_index,
                    min_index,
                    max_index,
                    predicate,
                ) {
                    return true;
                }
            }
            ArrayExpressionElement::Elision(_) => {
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
            element => {
                if position_can_match(wanted, *min_index, *max_index)
                    && element
                        .as_expression()
                        .is_some_and(|expr| predicate(syntax_index, expr))
                {
                    return true;
                }
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
        }
    }
    false
}

fn position_can_match(wanted: usize, min_index: usize, max_index: Option<usize>) -> bool {
    min_index <= wanted && max_index.is_none_or(|max_index| wanted <= max_index)
}

/// The body and selected parameter of an inline callback with a plain name.
fn inline_callback_parameter<'e>(expr: &'e Expression<'_>, index: usize) -> Option<(u32, &'e str)> {
    let (params, body) = match unparen(expr) {
        Expression::ArrowFunctionExpression(function) => (&function.params, &function.body),
        Expression::FunctionExpression(function) => (&function.params, function.body.as_ref()?),
        _ => return None,
    };
    let BindingPattern::BindingIdentifier(id) = &params.items.get(index)?.pattern else {
        return None;
    };
    Some((body.span.start, id.name.as_str()))
}

/// The body span start of an inline callback.
fn callback_body_start(expr: &Expression<'_>) -> Option<u32> {
    match unparen(expr) {
        Expression::ArrowFunctionExpression(function) => Some(function.body.span.start),
        Expression::FunctionExpression(function) => Some(function.body.as_ref()?.span.start),
        _ => None,
    }
}

/// The names a `data` listener appends each chunk to, as `d += c`,
/// `d = d + c` or `chunks.push(c)` (`c` or `c.toString()`), which an `end`
/// listener then reads. A name the listener declares itself is its own.
fn chunk_accumulators(expr: &Expression<'_>) -> Vec<String> {
    let (params, body) = match unparen(expr) {
        Expression::ArrowFunctionExpression(function) => (&function.params, &*function.body),
        Expression::FunctionExpression(function) => match &function.body {
            Some(body) => (&function.params, &**body),
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let Some((_, chunk)) = inline_callback_parameter(expr, 0) else {
        return Vec::new();
    };
    let mut local = function_local_binding_names(body);
    for parameter in &params.items {
        collect_binding_names(&parameter.pattern, &mut local);
    }
    let is_chunk = |value: &Expression<'_>| match unparen(value) {
        Expression::Identifier(id) => id.name.as_str() == chunk,
        Expression::CallExpression(call) => matches!(
            unparen(&call.callee),
            Expression::StaticMemberExpression(member)
                if member.property.name.as_str() == "toString"
                    && matches!(unparen(&member.object), Expression::Identifier(id) if id.name.as_str() == chunk)
        ),
        _ => false,
    };
    let mut names = Vec::new();
    for statement in &body.statements {
        let Statement::ExpressionStatement(statement) = statement else {
            continue;
        };
        let name = match unparen(&statement.expression) {
            Expression::AssignmentExpression(assignment) => {
                let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left else {
                    continue;
                };
                let name = target.name.as_str();
                let appends = match assignment.operator {
                    oxc_ast::ast::AssignmentOperator::Addition => is_chunk(&assignment.right),
                    oxc_ast::ast::AssignmentOperator::Assign => matches!(
                        unparen(&assignment.right),
                        Expression::BinaryExpression(sum)
                            if sum.operator == oxc_ast::ast::BinaryOperator::Addition
                                && matches!(unparen(&sum.left), Expression::Identifier(id) if id.name.as_str() == name)
                                && is_chunk(&sum.right)
                    ),
                    _ => false,
                };
                if !appends {
                    continue;
                }
                name
            }
            Expression::CallExpression(call) => {
                let Expression::StaticMemberExpression(member) = unparen(&call.callee) else {
                    continue;
                };
                let Expression::Identifier(target) = unparen(&member.object) else {
                    continue;
                };
                if member.property.name.as_str() != "push"
                    || !call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .is_some_and(is_chunk)
                {
                    continue;
                }
                target.name.as_str()
            }
            _ => continue,
        };
        if !local.contains(name) && !names.iter().any(|known| known == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// Whether a promise is known never to fulfill: a chain in which some
/// `.then` or `.finally` handler always throws and no later link recovers.
/// Nothing about a promise's origin is taken as proof, because any promise
/// exposes the runtime `Promise` through `.constructor`. `throws_reject`
/// is false when the program may replace how a handler's throw settles the
/// chain, and then nothing is proven.
fn promise_known_unfulfilled(receiver: &Expression<'_>, throws_reject: bool) -> bool {
    if !throws_reject {
        return false;
    }
    let mut links = Vec::new();
    let mut root = receiver;
    while let Expression::CallExpression(call) = unparen(root)
        && let Expression::StaticMemberExpression(member) = unparen(&call.callee)
        && matches!(member.property.name.as_str(), "then" | "catch" | "finally")
    {
        links.push((member.property.name.as_str(), call));
        root = &member.object;
    }
    let mut unfulfilled = false;
    for (method, call) in links.into_iter().rev() {
        let throws = |index: usize| {
            call.arguments
                .get(index)
                .and_then(Argument::as_expression)
                .is_some_and(handler_always_throws)
        };
        let present = |index: usize| call.arguments.get(index).is_some();
        unfulfilled = match method {
            // A rejection handler that may complete normally recovers the chain.
            "then" if unfulfilled => !present(1) || throws(1),
            "then" => throws(0),
            "catch" => unfulfilled && (!present(0) || throws(0)),
            _ => unfulfilled || throws(0),
        };
    }
    unfulfilled
}

/// Whether an inline handler's block body starts with a top-level `throw`,
/// so it throws before anything else can complete.
fn handler_always_throws(handler: &Expression<'_>) -> bool {
    let body = match unparen(handler) {
        Expression::ArrowFunctionExpression(function) if !function.expression => &*function.body,
        Expression::FunctionExpression(function) => match &function.body {
            Some(body) => &**body,
            None => return false,
        },
        _ => return false,
    };
    matches!(body.statements.first(), Some(Statement::ThrowStatement(_)))
}

/// Whether the program can be trusted not to replace how a promise handler's
/// `throw` settles its chain, such as through a replaced `then`. Any of these
/// lexical tripwires declines: the words `prototype`, `constructor`,
/// `__proto__`, `setPrototypeOf`, `defineProperty`, `defineProperties`,
/// `__defineGetter__`, `__defineSetter__` or `Reflect` anywhere in the
/// source; `then` assigned as a member or used as a property key; or a
/// computed member write whose key is not a literal.
fn throws_reject(program: &oxc_ast::ast::Program<'_>, source: &str) -> bool {
    const WORDS: [&str; 9] = [
        "prototype",
        "constructor",
        "__proto__",
        "setPrototypeOf",
        "defineProperty",
        "defineProperties",
        "__defineGetter__",
        "__defineSetter__",
        "Reflect",
    ];
    let identifier = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let has_word = |word: &str| {
        source.match_indices(word).any(|(at, _)| {
            !source[..at].ends_with(identifier)
                && !source[at + word.len()..].starts_with(identifier)
        })
    };
    if WORDS.iter().any(|word| has_word(word)) {
        return false;
    }
    #[derive(Default)]
    struct Tripwires {
        found: bool,
        depth: u32,
    }
    impl Tripwires {
        fn key_is_then(key: &PropertyKey<'_>) -> bool {
            key.static_name().is_some_and(|name| name == "then")
        }
    }
    impl<'a> Visit<'a> for Tripwires {
        fn visit_statement(&mut self, it: &Statement<'a>) {
            // Past the depth limit the program is not known to be free of them.
            if self.depth >= MAX_WALK_DEPTH {
                self.found = true;
                return;
            }
            self.depth += 1;
            walk::walk_statement(self, it);
            self.depth -= 1;
        }
        fn visit_expression(&mut self, it: &Expression<'a>) {
            if self.depth >= MAX_WALK_DEPTH {
                self.found = true;
                return;
            }
            self.depth += 1;
            walk::walk_expression(self, it);
            self.depth -= 1;
        }
        fn visit_simple_assignment_target(&mut self, it: &SimpleAssignmentTarget<'a>) {
            match it.as_member_expression() {
                Some(MemberExpression::StaticMemberExpression(member)) => {
                    self.found |= member.property.name.as_str() == "then";
                }
                Some(MemberExpression::ComputedMemberExpression(member)) => {
                    self.found |= match &member.expression {
                        Expression::StringLiteral(key) => key.value == "then",
                        Expression::NumericLiteral(_) => false,
                        _ => true,
                    };
                }
                _ => {}
            }
            walk::walk_simple_assignment_target(self, it);
        }
        fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
            self.found |= Self::key_is_then(&it.key);
            walk::walk_object_property(self, it);
        }
        fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
            self.found |= Self::key_is_then(&it.key);
            walk::walk_method_definition(self, it);
        }
        fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
            self.found |= Self::key_is_then(&it.key);
            walk::walk_property_definition(self, it);
        }
    }
    let mut tripwires = Tripwires::default();
    tripwires.visit_program(program);
    !tripwires.found
}

fn callback_needs_resolution(expr: &Expression<'_>) -> bool {
    match unparen(expr) {
        Expression::Identifier(id) => id.name.as_str() != "undefined",
        Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_)
        | Expression::CallExpression(_)
        | Expression::ChainExpression(_)
        | Expression::ConditionalExpression(_)
        | Expression::LogicalExpression(_)
        | Expression::SequenceExpression(_)
        | Expression::AssignmentExpression(_)
        | Expression::TaggedTemplateExpression(_) => true,
        Expression::AwaitExpression(awaited) => callback_needs_resolution(&awaited.argument),
        _ => false,
    }
}

/// Whether an expression is a `createServer(...)` call — bare or as a member
/// (`http.createServer`, `httpServer.createServer`). Creating a server is what
/// the name says regardless of which module wraps it.
fn is_create_server(expr: &Expression) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    match unparen(&call.callee) {
        Expression::Identifier(id) => id.name.as_str() == "createServer",
        Expression::StaticMemberExpression(m) => m.property.name.as_str() == "createServer",
        _ => false,
    }
}

/// Strip parentheses (the parser preserves them) to reach the real callee.
fn unparen<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unparen(&p.expression),
        Expression::TSAsExpression(e) => unparen(&e.expression),
        Expression::TSSatisfiesExpression(e) => unparen(&e.expression),
        Expression::TSTypeAssertion(e) => unparen(&e.expression),
        Expression::TSNonNullExpression(e) => unparen(&e.expression),
        Expression::TSInstantiationExpression(e) => unparen(&e.expression),
        other => other,
    }
}

fn sequence_callee_value<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    let expr = unparen(expr);
    match expr {
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .last()
            .map(sequence_callee_value)
            .unwrap_or(expr),
        _ => expr,
    }
}

fn assignment_flow_key(target: &AssignmentTarget<'_>) -> Option<String> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str().to_string()),
        AssignmentTarget::StaticMemberExpression(member) => {
            member_flow_key(&member.object, member.property.name.as_str())
        }
        AssignmentTarget::ComputedMemberExpression(member) => {
            let property = literal_property_name(&member.expression)?;
            member_flow_key(&member.object, &property)
        }
        AssignmentTarget::TSAsExpression(target) => expression_flow_key(&target.expression),
        AssignmentTarget::TSSatisfiesExpression(target) => expression_flow_key(&target.expression),
        AssignmentTarget::TSNonNullExpression(target) => expression_flow_key(&target.expression),
        AssignmentTarget::TSTypeAssertion(target) => expression_flow_key(&target.expression),
        _ => None,
    }
}

fn assignment_target_write_binding_name(target: &AssignmentTarget<'_>) -> Option<String> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str().to_string()),
        AssignmentTarget::StaticMemberExpression(member) => member_write_binding_name(
            &member.object,
            Some(member.property.name.as_str().to_string()),
        ),
        AssignmentTarget::ComputedMemberExpression(member) => {
            member_write_binding_name(&member.object, literal_property_name(&member.expression))
        }
        AssignmentTarget::TSAsExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        AssignmentTarget::TSSatisfiesExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        AssignmentTarget::TSNonNullExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        AssignmentTarget::TSTypeAssertion(target) => {
            expression_write_binding_name(&target.expression)
        }
        _ => None,
    }
}

fn simple_assignment_target_write_binding_name(
    target: &SimpleAssignmentTarget<'_>,
) -> Option<String> {
    match target {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
            Some(id.name.as_str().to_string())
        }
        SimpleAssignmentTarget::StaticMemberExpression(member) => member_write_binding_name(
            &member.object,
            Some(member.property.name.as_str().to_string()),
        ),
        SimpleAssignmentTarget::ComputedMemberExpression(member) => {
            member_write_binding_name(&member.object, literal_property_name(&member.expression))
        }
        SimpleAssignmentTarget::TSAsExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        SimpleAssignmentTarget::TSSatisfiesExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        SimpleAssignmentTarget::TSNonNullExpression(target) => {
            expression_write_binding_name(&target.expression)
        }
        SimpleAssignmentTarget::TSTypeAssertion(target) => {
            expression_write_binding_name(&target.expression)
        }
        _ => None,
    }
}

fn expression_write_binding_name(expression: &Expression<'_>) -> Option<String> {
    match unparen(expression) {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        Expression::StaticMemberExpression(member) => member_write_binding_name(
            &member.object,
            Some(member.property.name.as_str().to_string()),
        ),
        Expression::ComputedMemberExpression(member) => {
            member_write_binding_name(&member.object, literal_property_name(&member.expression))
        }
        _ => None,
    }
}

fn member_write_binding_name(object: &Expression<'_>, property: Option<String>) -> Option<String> {
    match property {
        Some(property) => member_flow_key(object, &property),
        None => expression_flow_key(object),
    }
}

fn expression_flow_key(expr: &Expression<'_>) -> Option<String> {
    match unparen(expr) {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        Expression::StaticMemberExpression(member) => {
            member_flow_key(&member.object, member.property.name.as_str())
        }
        Expression::ComputedMemberExpression(member) => {
            let property = literal_property_name(&member.expression)?;
            member_flow_key(&member.object, &property)
        }
        Expression::AwaitExpression(awaited) => expression_flow_key(&awaited.argument),
        _ => None,
    }
}

fn member_flow_key(object: &Expression<'_>, property: &str) -> Option<String> {
    let base = expression_flow_key(object)?;
    let name = format!("{base}.{property}");
    Some(canonical_global_builtin_binding(&name).unwrap_or(name))
}

fn canonical_global_builtin_binding(name: &str) -> Option<String> {
    let suffix = name.strip_prefix("globalThis.")?;
    let (builtin, member) = suffix.split_once('.').unwrap_or((suffix, ""));
    matches!(builtin, "Promise" | "String").then(|| {
        if member.is_empty() {
            builtin.to_string()
        } else {
            format!("{builtin}.{member}")
        }
    })
}

fn aggregate_mutation_target_bindings(call: &CallExpression<'_>) -> HashSet<String> {
    let mut bindings = HashSet::new();
    let callee_key = expression_flow_key(&call.callee);
    if let Some((target, method)) = callee_key
        .as_deref()
        .and_then(|callee| callee.rsplit_once('.'))
        && matches!(
            method,
            "fill" | "reverse" | "copyWithin" | "splice" | "shift" | "unshift" | "sort" | "pop"
        )
    {
        bindings.insert(target.to_string());
        return bindings;
    }
    if matches!(
        callee_key.as_deref(),
        Some(
            "Object.assign.apply" | "Object.defineProperty.apply" | "Object.defineProperties.apply"
        )
    ) {
        let arguments =
            logical_call_argument(&call.arguments, 1).and_then(|(argument, _)| argument);
        if let Some(arguments) = arguments
            && let Some(name) = array_element_binding(arguments, 0)
        {
            bindings.insert(name);
        }
        bindings.extend(
            logical_call_argument_bindings(&call.arguments, 1)
                .into_iter()
                .map(|name| format!("{name}.0")),
        );
        if callee_key.as_deref() == Some("Object.defineProperty.apply") {
            return defined_property_member_bindings(
                &bindings,
                arguments
                    .and_then(|arguments| array_element(arguments, 1))
                    .and_then(literal_property_name),
            );
        }
        return if callee_key.as_deref() == Some("Object.assign.apply") {
            static_object_member_bindings_from_array(&bindings, arguments, 1)
        } else {
            static_object_member_bindings(
                &bindings,
                arguments.and_then(|arguments| array_element(arguments, 1)),
            )
        };
    }
    let target_index = match callee_key.as_deref() {
        Some(
            "Object.assign.call" | "Object.defineProperty.call" | "Object.defineProperties.call",
        ) => 1,
        Some(
            "Object.assign"
            | "Object.defineProperty"
            | "Object.defineProperties"
            | "Array.prototype.fill.call"
            | "Array.prototype.fill.apply"
            | "Array.prototype.reverse.call"
            | "Array.prototype.reverse.apply"
            | "Array.prototype.splice.call"
            | "Array.prototype.splice.apply"
            | "Array.prototype.copyWithin.call"
            | "Array.prototype.copyWithin.apply"
            | "Array.prototype.shift.call"
            | "Array.prototype.shift.apply"
            | "Array.prototype.unshift.call"
            | "Array.prototype.unshift.apply"
            | "Array.prototype.sort.call"
            | "Array.prototype.sort.apply"
            | "Array.prototype.pop.call"
            | "Array.prototype.pop.apply",
        ) => 0,
        _ => return bindings,
    };
    bindings.extend(logical_call_argument_bindings(
        &call.arguments,
        target_index,
    ));
    let property_index = match callee_key.as_deref() {
        Some("Object.defineProperty") => Some(1),
        Some("Object.defineProperty.call") => Some(2),
        _ => None,
    };
    if let Some(property_index) = property_index {
        return defined_property_member_bindings(
            &bindings,
            logical_call_argument(&call.arguments, property_index)
                .and_then(|(argument, _)| argument)
                .and_then(literal_property_name),
        );
    }
    match callee_key.as_deref() {
        Some("Object.assign") => {
            return static_object_member_bindings_from_arguments(&bindings, &call.arguments, 1);
        }
        Some("Object.assign.call") => {
            return static_object_member_bindings_from_arguments(&bindings, &call.arguments, 2);
        }
        Some("Object.defineProperties") => {
            return static_object_member_bindings(
                &bindings,
                logical_call_argument(&call.arguments, 1).and_then(|(argument, _)| argument),
            );
        }
        Some("Object.defineProperties.call") => {
            return static_object_member_bindings(
                &bindings,
                logical_call_argument(&call.arguments, 2).and_then(|(argument, _)| argument),
            );
        }
        _ => {}
    }
    bindings
}

fn defined_property_member_bindings(
    targets: &HashSet<String>,
    property: Option<String>,
) -> HashSet<String> {
    let mut bindings = targets.clone();
    let Some(property) = property else {
        // An unknown property may replace either transparent builtin.
        for property in ["String", "Promise"] {
            for target in targets {
                let member = format!("{target}.{property}");
                bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
            }
        }
        return bindings;
    };
    for target in targets {
        let member = format!("{target}.{property}");
        bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
    }
    bindings
}

fn static_object_member_bindings(
    targets: &HashSet<String>,
    object: Option<&Expression<'_>>,
) -> HashSet<String> {
    let mut bindings = targets.clone();
    let mut has_unbounded_properties = false;
    if let Some(Expression::ObjectExpression(object)) = object.map(unparen) {
        for property in &object.properties {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property else {
                has_unbounded_properties = true;
                continue;
            };
            let Some(property) = property.key.static_name() else {
                has_unbounded_properties = true;
                continue;
            };
            for target in targets {
                let member = format!("{target}.{property}");
                bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
            }
        }
    } else {
        has_unbounded_properties = true;
    }
    if has_unbounded_properties {
        // An unprojectable bulk source may replace either transparent builtin.
        for property in ["String", "Promise"] {
            for target in targets {
                let member = format!("{target}.{property}");
                bindings.insert(canonical_global_builtin_binding(&member).unwrap_or(member));
            }
        }
    }
    bindings
}

fn static_object_member_bindings_from_arguments(
    targets: &HashSet<String>,
    arguments: &[Argument<'_>],
    first_source: usize,
) -> HashSet<String> {
    let Some(argument_count) = logical_call_argument_count(arguments) else {
        return static_object_member_bindings(targets, None);
    };
    let mut bindings = targets.clone();
    for index in first_source..argument_count {
        bindings.extend(static_object_member_bindings(
            targets,
            logical_call_argument(arguments, index).and_then(|(argument, _)| argument),
        ));
    }
    bindings
}

fn static_object_member_bindings_from_array(
    targets: &HashSet<String>,
    array: Option<&Expression<'_>>,
    first_source: usize,
) -> HashSet<String> {
    let Some(array) = array else {
        return static_object_member_bindings(targets, None);
    };
    let Some(argument_count) = array_literal_len(array) else {
        return static_object_member_bindings(targets, None);
    };
    let mut bindings = targets.clone();
    for index in first_source..argument_count {
        bindings.extend(static_object_member_bindings(
            targets,
            array_element(array, index),
        ));
    }
    bindings
}

fn literal_property_name(expr: &Expression<'_>) -> Option<String> {
    match unparen(expr) {
        Expression::StringLiteral(value) => Some(value.value.as_str().to_string()),
        Expression::NumericLiteral(value) => Some(value.value.to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => Some(
            template
                .quasis
                .first()?
                .value
                .cooked
                .as_ref()?
                .as_str()
                .to_string(),
        ),
        _ => None,
    }
}

fn array_element<'a, 'b>(expr: &'b Expression<'a>, wanted: usize) -> Option<&'b Expression<'a>> {
    match unparen(expr) {
        Expression::AwaitExpression(awaited) => array_element(&awaited.argument, wanted),
        Expression::ArrayExpression(array) => {
            let mut index = 0;
            for element in &array.elements {
                match element {
                    oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                        let len = array_literal_len(&spread.argument)?;
                        if wanted < index + len {
                            return array_element(&spread.argument, wanted - index);
                        }
                        index += len;
                    }
                    oxc_ast::ast::ArrayExpressionElement::Elision(_) => index += 1,
                    element => {
                        if index == wanted {
                            return element.as_expression();
                        }
                        index += 1;
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn array_element_binding(expr: &Expression<'_>, wanted: usize) -> Option<String> {
    array_element(expr, wanted)
        .and_then(expression_flow_key)
        .or_else(|| Some(format!("{}.{}", expression_flow_key(expr)?, wanted)))
}

fn array_literal_len(expr: &Expression<'_>) -> Option<usize> {
    let Expression::ArrayExpression(array) = unparen(expr) else {
        return None;
    };
    let mut len = 0;
    for element in &array.elements {
        len += match element {
            oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                array_literal_len(&spread.argument)?
            }
            _ => 1,
        };
    }
    Some(len)
}

fn array_element_is_string_concatenation(
    expr: &Expression<'_>,
    wanted: usize,
    source_env: &ParamEnv,
    evaluated: &EvaluatedSourceStrings,
) -> bool {
    let mut min_index = 0;
    let mut max_index = Some(0);
    array_elements_at_position_match(
        expr,
        wanted,
        0,
        &mut min_index,
        &mut max_index,
        &mut |_, expression| is_string_concatenation(expression, source_env, evaluated),
    )
}

enum ObjectPropertyProjection<'r, 'a> {
    Value(&'r Expression<'a>),
    Missing,
    Unbounded,
}

fn object_property_projection<'r, 'a>(
    expr: &'r Expression<'a>,
    wanted: &str,
) -> ObjectPropertyProjection<'r, 'a> {
    match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            object_property_projection(&awaited.argument, wanted)
        }
        Expression::ObjectExpression(object) => {
            for property in object.properties.iter().rev() {
                match property {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                        match property.key.static_name() {
                            Some(name) if name == wanted => {
                                return ObjectPropertyProjection::Value(&property.value);
                            }
                            Some(_) => {}
                            None => return ObjectPropertyProjection::Unbounded,
                        }
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                        match object_property_projection(&spread.argument, wanted) {
                            ObjectPropertyProjection::Missing => {}
                            projection => return projection,
                        }
                    }
                }
            }
            ObjectPropertyProjection::Missing
        }
        _ => ObjectPropertyProjection::Unbounded,
    }
}

fn object_property_is_string_concatenation(
    expr: &Expression<'_>,
    wanted: &str,
    source_env: &ParamEnv,
    evaluated: &EvaluatedSourceStrings,
) -> bool {
    let object = match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            return object_property_is_string_concatenation(
                &awaited.argument,
                wanted,
                source_env,
                evaluated,
            );
        }
        Expression::ObjectExpression(object) => object,
        _ => return false,
    };
    for property in object.properties.iter().rev() {
        match property {
            oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                match property.key.static_name() {
                    Some(name) if name == wanted => {
                        return is_string_concatenation(&property.value, source_env, evaluated);
                    }
                    Some(_) => {}
                    None => {}
                }
            }
            oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                match object_property_projection(&spread.argument, wanted) {
                    ObjectPropertyProjection::Value(value) => {
                        return is_string_concatenation(value, source_env, evaluated);
                    }
                    ObjectPropertyProjection::Missing => {}
                    ObjectPropertyProjection::Unbounded => {
                        if object_property_is_string_concatenation(
                            &spread.argument,
                            wanted,
                            source_env,
                            evaluated,
                        ) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn object_property<'a, 'b>(expr: &'b Expression<'a>, wanted: &str) -> Option<&'b Expression<'a>> {
    match object_property_projection(expr, wanted) {
        ObjectPropertyProjection::Value(value) => Some(value),
        ObjectPropertyProjection::Missing | ObjectPropertyProjection::Unbounded => None,
    }
}

fn js_guard_regions(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    throws_reject: bool,
    bindings: &Bindings,
) -> crate::guards::GuardRegions {
    use effinterp_proto::{ByteSpan, ConditionKind};
    fn span(value: &impl GetSpan) -> ByteSpan {
        ByteSpan {
            start: value.span().start,
            end: value.span().end,
        }
    }
    struct JsGuardRegionCollector<'s> {
        source: &'s str,
        bindings: &'s Bindings,
        throws_reject: bool,
        guards: crate::guards::GuardRegions,
        depth: usize,
        /// Functions invoked where they are written, whose bodies run at the call.
        immediate: HashSet<u32>,
        /// First handlers of `.then(...)`, which run once the promise fulfills,
        /// and candidate `http(s).get` response handlers and listeners.
        fulfillment: HashSet<u32>,
    }
    impl JsGuardRegionCollector<'_> {
        fn function_region(&mut self, origin: ByteSpan, body: ByteSpan) {
            if self.immediate.contains(&origin.start) {
                return;
            }
            // Like the right side of `&&`, a fulfillment handler runs only on
            // success; any other callback may or may not be dispatched.
            let (kind, positive) = if self.fulfillment.contains(&origin.start) {
                (ConditionKind::ShortCircuit, true)
            } else {
                (ConditionKind::Dispatch, false)
            };
            self.guards
                .add(self.source, origin, body, kind, 0, 2, positive);
        }
    }
    impl<'a> Visit<'a> for JsGuardRegionCollector<'_> {
        fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
            let callee = unparen(&it.callee);
            if matches!(
                callee,
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            ) {
                self.immediate.insert(callee.span().start);
            }
            if let Expression::StaticMemberExpression(member) = callee
                && member.property.name.as_str() == "then"
                && !promise_known_unfulfilled(&member.object, self.throws_reject)
                && let Some(handler) = it.arguments.first().and_then(Argument::as_expression)
            {
                self.fulfillment.insert(unparen(handler).span().start);
            }
            // Use the same module binding resolver as the effect walk, so
            // named imports, destructuring, aliases and computed members
            // receive the same callback condition.
            if let Some(target) = resolve::resolve_callee(callee, self.bindings)
                && ((target.module == "fs"
                    && target.function == "readFile"
                    && matches!(it.arguments.len(), 2 | 3))
                    || (matches!(target.module.as_str(), "http" | "https")
                        && target.function == "get"
                        && it.arguments.len() > 1))
                && let Some(handler) = it.arguments.last().and_then(Argument::as_expression)
            {
                self.fulfillment.insert(unparen(handler).span().start);
            }
            // The walk resolves message listeners; other callbacks keep
            // their dispatch condition.
            if let Expression::StaticMemberExpression(member) = callee {
                let handler = match member.property.name.as_str() {
                    "on" | "once"
                        if it.arguments.first().is_some_and(|event| {
                            matches!(event, Argument::StringLiteral(event)
                                if matches!(event.value.as_str(), "data" | "end"))
                        }) =>
                    {
                        it.arguments.get(1)
                    }
                    _ => None,
                };
                if let Some(handler) = handler.and_then(Argument::as_expression) {
                    self.fulfillment.insert(unparen(handler).span().start);
                }
            }
            walk::walk_call_expression(self, it);
        }
        fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
            self.guards.add(
                self.source,
                span(it),
                span(it.body.as_ref()),
                ConditionKind::UnresolvedExecution,
                0,
                2,
                false,
            );
            walk::walk_catch_clause(self, it);
        }
        fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
            for statement in &it.statements {
                if let Statement::IfStatement(branch) = statement {
                    let yes = statement_stops_sequential_execution(&branch.consequent);
                    let no = branch
                        .alternate
                        .as_ref()
                        .is_some_and(statement_stops_sequential_execution);
                    if yes != no {
                        self.guards.add(
                            self.source,
                            span(branch.as_ref()),
                            ByteSpan {
                                start: branch.span.end,
                                end: it.span.end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
            walk::walk_function_body(self, it);
        }
        fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
            for statement in &it.body {
                if let Statement::IfStatement(branch) = statement {
                    let yes = statement_stops_sequential_execution(&branch.consequent);
                    let no = branch
                        .alternate
                        .as_ref()
                        .is_some_and(statement_stops_sequential_execution);
                    if yes != no {
                        self.guards.add(
                            self.source,
                            span(branch.as_ref()),
                            ByteSpan {
                                start: branch.span.end,
                                end: it.span.end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
            walk::walk_block_statement(self, it);
        }
        fn visit_expression(&mut self, it: &Expression<'a>) {
            if self.depth >= MAX_WALK_DEPTH as usize {
                self.guards.widen();
                return;
            }
            self.depth += 1;
            match it {
                Expression::ArrowFunctionExpression(e) => {
                    self.function_region(span(e.as_ref()), span(e.body.as_ref()))
                }
                Expression::FunctionExpression(e) => {
                    if let Some(body) = &e.body {
                        self.function_region(span(e.as_ref()), span(body.as_ref()));
                    }
                }
                Expression::LogicalExpression(e) => self.guards.add(
                    self.source,
                    span(e.as_ref()),
                    span(&e.right),
                    ConditionKind::ShortCircuit,
                    u32::from(e.operator != oxc_ast::ast::LogicalOperator::And),
                    2,
                    true,
                ),
                Expression::ConditionalExpression(e) => {
                    self.guards.add(
                        self.source,
                        span(e.as_ref()),
                        span(&e.consequent),
                        ConditionKind::Branch,
                        0,
                        2,
                        true,
                    );
                    self.guards.add(
                        self.source,
                        span(e.as_ref()),
                        span(&e.alternate),
                        ConditionKind::Branch,
                        1,
                        2,
                        true,
                    );
                }
                _ => (),
            }
            walk::walk_expression(self, it);
            self.depth -= 1;
        }
        fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
            // A literal test always selects one arm, which then runs
            // unconditionally; the effect walk never enters the other.
            if literal_truth(&it.test).is_some() {
                walk::walk_if_statement(self, it);
                return;
            }
            self.guards.add(
                self.source,
                span(it),
                span(&it.consequent),
                ConditionKind::Branch,
                0,
                2,
                true,
            );
            if let Some(other) = &it.alternate {
                self.guards.add(
                    self.source,
                    span(it),
                    span(other),
                    ConditionKind::Branch,
                    1,
                    2,
                    true,
                );
            }
            walk::walk_if_statement(self, it);
        }
        fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
            self.guards.add(
                self.source,
                span(it),
                span(&it.body),
                ConditionKind::Loop,
                0,
                2,
                false,
            );
            walk::walk_while_statement(self, it);
        }
        fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
            self.guards.add(
                self.source,
                span(it),
                span(&it.body),
                ConditionKind::Loop,
                0,
                2,
                false,
            );
            walk::walk_for_statement(self, it);
        }
        fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
            for region in [span(&it.left), span(&it.body)] {
                self.guards.add(
                    self.source,
                    span(it),
                    region,
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                );
            }
            walk::walk_for_of_statement(self, it);
        }
        fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
            for region in [span(&it.left), span(&it.body)] {
                self.guards.add(
                    self.source,
                    span(it),
                    region,
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                );
            }
            walk::walk_for_in_statement(self, it);
        }
        fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
            for (arm, case) in it.cases.iter().enumerate() {
                if arm > 0
                    && !it.cases[arm - 1]
                        .consequent
                        .last()
                        .is_some_and(statement_stops_sequential_execution)
                {
                    self.guards.add_unknown(span(case));
                    continue;
                }

                self.guards.add(
                    self.source,
                    span(it),
                    span(case),
                    ConditionKind::Branch,
                    arm as u32,
                    it.cases.len() as u32
                        + u32::from(!it.cases.iter().any(|case| case.test.is_none())),
                    false,
                );
            }
            walk::walk_switch_statement(self, it);
        }
    }
    let mut collector = JsGuardRegionCollector {
        source,
        bindings,
        throws_reject,
        guards: Default::default(),
        depth: 0,
        immediate: HashSet::new(),
        fulfillment: HashSet::new(),
    };
    collector.visit_program(program);
    collector.guards
}
