//! Invocation walking and effect emission in source order.

mod builtin_effects;
mod call_resolution;
mod class_dispatch;
pub(super) mod environment;
mod includes;
mod local_bindings;
pub(super) mod resource_recovery;
mod shell_output;

use std::collections::{HashMap, HashSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ProvenanceKind, ProvenanceRef, ResourceExpr,
};
use tree_sitter::Node;

use crate::SemanticValue;
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::SiteFacts;
use crate::lang::conditions::tree_condition;
use crate::lang::frontend::{FrontendInput, WalkOutcome};
use crate::lang::tree_sitter_nodes::node_span;
use crate::nest::Nest;
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::summary::substitute_resource_expr;

use super::DOMAINS;
use super::control;
use super::file_context::{PhpFileContext, collect_php_file_context};
use super::syntax::{param_names, text};
use call_resolution::{
    PhpClosure, PhpFunction, closure_uses, collect_php_functions, declared_php_callable_names,
};
use class_dispatch::php_framework_roots;
use resource_recovery::fold_host_path;
use shell_output::{
    PhpHeldCapture, PhpValueFacts, capture_sources, literal_truth, prints_to_stdout,
};

/// Walk reached PHP code under one invocation budget, sharing the source state
/// with nested includes and class calls. Only a root file seeds console entry points.
pub(super) fn walk_php_file(
    builder: &mut PlanBuilder,
    nest: &Nest,
    input: &FrontendInput,
    tree: &tree_sitter::Tree,
    inc: &mut PhpSourceState,
    root_file: bool,
) -> WalkOutcome {
    let source = input.source;
    let source_cwd = input.source_cwd;
    let runtime_cwd = input.runtime_cwd;
    let cwd_node = input.cwd_node;
    let scope = input.scope;
    let depth = input.depth;
    let root = tree.root_node();
    if root_file
        && root
            .named_children(&mut root.walk())
            .all(|child| child.kind() == "text")
    {
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::UNSUPPORTED_SOURCE,
                class: BoundaryClass::ParseFailure,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: scope.as_slice().to_vec(),
                limit: None,
                detail: Some("php source has no <?php open tag".to_string()),
            },
            CoverageLevel::None,
        );
        return WalkOutcome::default();
    }
    let functions = collect_php_functions(root, source);
    let declared_callables = root_file.then(|| declared_php_callable_names(root, source));
    let ctx = collect_php_file_context(root, source);
    inc.consts.extend(ctx.top_consts.clone());
    let runtime_cwd_resource = builder.current_execution_cwd();
    let first_effect = builder.effects_len();
    let mut c = root.walk();
    let children: Vec<Node> = root.named_children(&mut c).collect();
    builder.control_enter(source, false, |graph| {
        control::build_php_control_flow(graph, &children, source)
    });
    let mut w = PhpWalker {
        control_applications: Vec::new(),
        builder,
        nest,
        src: source,
        root,
        source_cwd,
        runtime_cwd,
        runtime_cwd_resource,
        cwd_node,
        scope,
        depth,
        functions: &functions,
        following: HashSet::new(),
        entered_callables: HashSet::new(),
        call_depth: 0,
        nodes: nest.limits.max_php_nodes,
        reported: HashSet::new(),
        inc,
        ctx,
        current_class: None,
        class_parent: None,
        vars: HashMap::new(),
        locals: HashMap::new(),
        network_handles: HashMap::new(),
        eval_code: HashMap::new(),
        request_bodies: HashMap::new(),
        examined_contexts: HashSet::new(),
        poisoned: HashSet::new(),
        closures: HashMap::new(),
        handled_closures: HashSet::new(),
        active_closures: HashSet::new(),
        truncated: false,
        environment_rewritten: false,
        printed_captures: HashSet::new(),
        captured_outputs: HashMap::new(),
        capture_locals: HashMap::new(),
        truth_locals: HashMap::new(),
        globals_written: false,
        global_facts: None,
    };
    // Execute the top level: statements outside any function definition.
    w.exec_statements(&children, &HashMap::new());
    w.builder.control_leave();
    if root_file {
        for (class, method, site) in php_framework_roots(root, source, &w.ctx) {
            w.dispatch_local_php_method(&class, &method, &[], site);
        }
    }
    let entered_callables = !w.entered_callables.is_empty();
    drop(w);
    for domain in DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    WalkOutcome {
        declared_callables: declared_callables
            .filter(|names| {
                !names.is_empty() && !entered_callables && builder.effects_len() == first_effect
            })
            .unwrap_or_default(),
    }
}

/// Source state shared by the root invocation, its includes, and PSR-4 class calls.
/// A constant defined by a wrapper can resolve paths in the files it includes.
#[derive(Default)]
pub(crate) struct PhpSourceState {
    included: HashSet<String>,
    stack: Vec<String>,
    consts: HashMap<String, String>,
    /// `autoload.psr-4` of the root composer.json (prefix -> dir), longest
    /// prefix first; None until first needed.
    psr4: Option<Vec<(String, String)>>,
    /// Resolved-source cache for class files (repeated dispatch re-parses,
    /// but reads each file once).
    sources: HashMap<String, Option<String>>,
    /// Class-method dispatches already analyzed (`path#class#method#args`).
    dispatched: HashSet<String>,
    /// Dispatches currently executing, for recursion cycles.
    dispatch_stack: Vec<String>,
    /// Last constructor-derived instance-property values for each class.
    props: HashMap<String, HashMap<String, ResourceExpr>>,
}

struct PhpWalker<'a, 'b> {
    builder: &'b mut PlanBuilder,
    nest: &'b Nest<'b>,
    src: &'a str,
    root: Node<'a>,
    source_cwd: Option<&'a str>,
    runtime_cwd: Option<&'a str>,
    runtime_cwd_resource: Option<ResourceExpr>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    functions: &'b HashMap<String, PhpFunction<'a>>,
    following: HashSet<String>,
    entered_callables: HashSet<String>,
    call_depth: u64,
    nodes: u64,
    reported: HashSet<String>,
    inc: &'b mut PhpSourceState,
    ctx: PhpFileContext,
    /// Exact class whose method is currently executing in this file.
    current_class: Option<String>,
    /// Resolved base class of the class whose method is executing.
    class_parent: Option<String>,
    /// Variables holding instances of resolvable classes (`$x = new C()`).
    vars: HashMap<String, Vec<String>>,
    locals: HashMap<String, ResourceExpr>,
    /// Locals bound to network handles and their connection/request endpoint.
    network_handles: HashMap<String, ResourceExpr>,
    /// The argument expressions of `eval`s this walk has entered, by node id,
    /// with the code execution each one's value becomes.
    eval_code: HashMap<usize, u32>,
    /// Inline content expressions whose bytes an HTTP stream sends.
    request_bodies: HashMap<usize, Vec<u32>>,
    /// Inline contexts whose HTTP content was examined by file_get_contents.
    examined_contexts: HashSet<usize>,
    poisoned: HashSet<String>,
    /// Locals holding exact anonymous or arrow-function bodies.
    closures: HashMap<String, Vec<PhpClosure<'a>>>,
    /// Closure nodes already deferred or invoked through exact evidence.
    handled_closures: HashSet<usize>,
    active_closures: HashSet<usize>,
    truncated: bool,
    /// Guarantees of bodies entered since the enclosing call began.
    control_applications: Vec<SiteFacts>,
    /// The program wrote the environment, so a value the host supplied may no
    /// longer be what a later `getenv` returns.
    environment_rewritten: bool,
    /// Capture sites a later output call prints: their commands run with the
    /// program's stdout instead of a captured one.
    printed_captures: HashSet<(usize, usize)>,
    /// Each captured command's child execution and the stdout it would have
    /// inherited, so printing the captured value can reconnect it.
    captured_outputs: HashMap<
        (usize, usize),
        (
            effinterp_proto::ExecutionNodeRef,
            Option<effinterp_proto::ExecutionStreamRef>,
        ),
    >,
    /// Capture sites whose output a local may hold, each with whether the
    /// local holds those bytes verbatim.
    capture_locals: HashMap<String, Vec<PhpHeldCapture>>,
    /// Locals whose last definite assignment was a literal, with its PHP
    /// truth value, so `print_r`'s return mode can be read from them.
    truth_locals: HashMap<String, bool>,
    /// Code since the enclosing call began wrote through `global` or
    /// `$GLOBALS`, so the caller's value facts may be stale.
    globals_written: bool,
    /// Inside a call, the top-level scope's value facts as the outermost call
    /// began, which a `global` declaration binds to.
    global_facts: Option<PhpValueFacts>,
}

/// How the walker evaluated a call, for its control-flow site.
#[derive(Clone, Copy)]
enum PhpCall {
    /// A direct builtin interaction with explicit local reachability evidence.
    Sink,
    /// A modeled builtin that runs no user code.
    Modeled,
    /// A dispatch whose one entered body answers for the call.
    Entered,
    /// Code the walker cannot see.
    Opaque,
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// Evaluate a call-like construct and register what it establishes.
    fn control_call(&mut self, n: Node<'a>, run: impl FnOnce(&mut Self) -> PhpCall) {
        let since = self.builder.control_registered();
        let before = self.builder.effects_len();
        let saved = std::mem::take(&mut self.control_applications);
        let kind = run(self);
        let applied = std::mem::replace(&mut self.control_applications, saved);
        let facts = match (kind, applied.as_slice()) {
            (PhpCall::Sink, []) => SiteFacts::known(
                self.builder
                    .control_own_effects(before..self.builder.effects_len()),
            ),
            (PhpCall::Modeled, []) => SiteFacts::known(Vec::new()),
            (PhpCall::Entered, [entered]) => entered.clone(),
            _ => SiteFacts::unknown(),
        };
        self.builder
            .control_site_since(self.src, false, node_span(n), since, facts);
    }

    /// A construct whose own modeled occurrences are all it reaches.
    fn control_modeled(&mut self, n: Node<'a>, run: impl FnOnce(&mut Self)) {
        self.control_call(n, |walker| {
            run(walker);
            PhpCall::Modeled
        });
    }

    /// Run a callable body in its own control-flow frame.
    fn control_body(&mut self, body: Node<'a>, run: impl FnOnce(&mut Self)) {
        self.builder.control_enter(self.src, false, |graph| {
            let statements: Vec<Node> = if body.kind() == "compound_statement" {
                let mut cursor = body.walk();
                body.named_children(&mut cursor).collect()
            } else {
                vec![body]
            };
            control::build_php_control_flow(graph, &statements, self.src)
        });
        run(self);
        let application = match self.builder.control_leave() {
            Some(finished) => SiteFacts::call(&finished.requirements, Some),
            None => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
    }

    fn exec_statements(&mut self, nodes: &[Node<'a>], env: &HashMap<String, ResourceExpr>) {
        for n in nodes {
            self.exec(*n, env);
        }
    }

    fn exec(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        let depth = self.builder.condition_depth();
        self.exec_nodes(n, env);
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    fn exec_nodes(&mut self, n: Node<'a>, env: &HashMap<String, ResourceExpr>) {
        // Iterative: PHP `.` and nested statements are left-deep CST spines.
        // A 20k concat overflows an 8MiB stack before the node cap can fire.
        let mut stack = vec![n];
        let depth = self.builder.condition_depth();
        while let Some(n) = stack.pop() {
            while self.builder.condition_depth() > depth {
                self.builder.pop_condition();
            }
            let executes = matches!(
                n.kind(),
                "anonymous_function"
                    | "arrow_function"
                    | "function_call_expression"
                    | "member_call_expression"
                    | "scoped_call_expression"
                    | "object_creation_expression"
                    | "assignment_expression"
                    | "augmented_assignment_expression"
                    | "unset_statement"
                    | "subscript_expression"
                    | "shell_command_expression"
                    | "require_expression"
                    | "include_expression"
                    | "require_once_expression"
                    | "include_once_expression"
            ) || n.kind() == "variable_name" && !self.closures.is_empty();
            if executes && let Some(condition) = tree_condition(self.src, n) {
                self.builder.push_condition(condition);
            }
            if !crate::nest::charge_analysis_steps(
                self.builder,
                self.nest.budget,
                1,
                Some((n.start_byte() as u32, n.end_byte() as u32)),
            ) {
                self.truncated = true;
                return;
            }
            if self.nodes == 0 || !crate::limits::summary_step() {
                if !self.truncated {
                    self.truncated = true;
                    self.opaque(
                        BoundaryReason::PARTIAL_ANALYSIS,
                        BoundaryClass::Unmodeled,
                        n,
                    );
                }
                return;
            }
            self.nodes -= 1;
            if prints_to_stdout(n, self.src) {
                self.print_php_captured_output(n);
            }
            if n.kind() == "assignment_expression"
                && let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                )
                && left.kind() == "variable_name"
            {
                // A definite assignment replaces what the local held; a
                // conditional one may leave the earlier output in place.
                let (spans, locals) = capture_sources(right, self.src);
                let mut held = spans;
                for (local, exact) in locals {
                    held.extend(
                        self.capture_locals
                            .get(&local)
                            .into_iter()
                            .flatten()
                            .map(|&(span, verbatim)| (span, exact && verbatim)),
                    );
                }
                let name = text(left, self.src).to_string();
                let conditional = tree_condition(self.src, n).is_some();
                if conditional {
                    held.extend(self.capture_locals.get(&name).cloned().unwrap_or_default());
                }
                match literal_truth(right, self.src).filter(|_| !conditional) {
                    Some(truth) => self.truth_locals.insert(name.clone(), truth),
                    None => self.truth_locals.remove(&name),
                };
                self.capture_locals.insert(name, held);
            }
            self.forget_written(n);
            if n.kind() == "unset_statement" {
                let mut cursor = n.walk();
                for variable in n.named_children(&mut cursor) {
                    self.capture_locals.remove(text(variable, self.src));
                    self.truth_locals.remove(text(variable, self.src));
                }
            }
            // Named declarations execute only through `follow`. Exact stored
            // closures stay deferred; other closure literals remain bounded
            // callback candidates, preserving effects without name guessing.
            match n.kind() {
                "function_definition"
                | "method_declaration"
                | "class_declaration"
                | "interface_declaration"
                | "trait_declaration" => continue,
                "anonymous_function" | "arrow_function" => {
                    if !self.handled_closures.contains(&n.id())
                        && let Some(body) = n.child_by_field_name("body")
                    {
                        let params = n
                            .child_by_field_name("parameters")
                            .map(|parameters| param_names(parameters, self.src))
                            .unwrap_or_default();
                        self.run_closure(
                            &PhpClosure {
                                params,
                                body,
                                uses: closure_uses(n, self.src),
                            },
                            &[],
                        );
                    }
                    continue;
                }
                "function_call_expression" => {
                    self.control_call(n, |w| w.resolve_php_function_call(n, env))
                }
                "member_call_expression" | "scoped_call_expression" => self.control_call(n, |w| {
                    w.dispatch_php_method_call(n, env);
                    PhpCall::Entered
                }),
                "object_creation_expression" => {
                    self.control_call(n, |w| w.dispatch_php_constructor(n, env))
                }
                "assignment_expression" => {
                    self.control_modeled(n, |w| w.bind_php_assignment(n, env))
                }
                "augmented_assignment_expression" => {
                    self.control_modeled(n, |w| w.augmented_assign(n, env))
                }
                "unset_statement" => self.unset(n),
                "global_declaration" | "static_variable_declaration" => {
                    self.poison_declared_locals(n)
                }
                "variable_name" => self.run_escaped_closure(n),
                "subscript_expression" => self.control_modeled(n, |w| w.read_php_superglobal(n)),
                "shell_command_expression" => self.control_modeled(n, |w| {
                    let mut values = env.clone();
                    values.extend(w.locals.clone());
                    let cmd = w.interpolate(n, &values);
                    let environment = w.php_interpolation_environment(n, &values);
                    w.nest_php_shell_command(cmd, n, environment, true);
                }),
                "require_expression" | "include_expression" => {
                    self.follow_php_include(n, false, env);
                    continue;
                }
                "require_once_expression" | "include_once_expression" => {
                    self.follow_php_include(n, true, env);
                    continue;
                }
                _ => {}
            }
            let mut c = n.walk();
            let children: Vec<Node> = n.named_children(&mut c).collect();
            for ch in children.into_iter().rev() {
                stack.push(ch);
            }
        }
    }

    /// Emit one effect and report its plan slot, so a transfer emitter can
    /// pair the endpoints it just produced.
    fn emit(&mut self, effect: Effect, site: Node<'a>) -> Option<u32> {
        self.emit_applying(effect, site, None)
    }

    /// `emit`, attributing the effect to the named model's application.
    fn emit_applying(
        &mut self,
        mut effect: Effect,
        site: Node<'a>,
        model: Option<&str>,
    ) -> Option<u32> {
        let mut guard = tree_condition(self.src, site);
        self.builder.bind_source_condition(&mut guard);
        effect.condition =
            effinterp_proto::Condition::compose(effect.condition.iter().chain(guard.iter()));
        let mut environment_nodes = Vec::new();
        if effect.operation.as_str() == "environment.write" {
            self.environment_rewritten = true;
        } else if effect.operation.domain() == "filesystem"
            && self.resolve_host_environment(&mut effect.resource, &mut environment_nodes)
        {
            effect.resource = fold_host_path(effect.resource);
        }
        let uses_cwd =
            effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource);
        if uses_cwd && let Some(cwd) = &self.runtime_cwd_resource {
            effect.resource = substitute_resource_expr(
                &effect.resource,
                &HashMap::from([("cwd".to_string(), cwd.clone())]),
            );
        }
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        let node = self.span(site);
        effect.provenance = vec![node];
        effect.provenance.extend(model.map(|model| {
            self.builder.node(
                ProvenanceKind::ModelApplication {
                    model: model.to_string(),
                },
                &[node],
            )
        }));
        effect.provenance.extend(environment_nodes);
        if uses_cwd {
            effect.provenance.extend(self.cwd_node);
        }
        self.builder.effect(effect)
    }

    /// Record that `source` is the source side of one modeled transfer whose
    /// destination side is `destination`.
    fn record_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        if let (Some(source), Some(destination)) = (source, destination) {
            self.builder
                .transfer_binding(TransferBinding::new(source, destination));
        }
    }

    fn span(&mut self, n: Node<'a>) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: n.start_byte() as u32,
                end: n.end_byte() as u32,
            },
            self.scope.as_slice(),
        )
    }

    fn opaque(&mut self, reason: BoundaryReason, class: BoundaryClass, site: Node<'a>) {
        self.opaque_with_detail(reason, class, site, None);
    }

    fn opaque_with_detail(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        site: Node<'a>,
        detail: Option<String>,
    ) {
        if !self
            .reported
            .insert(format!("{reason}:{}", site.start_byte()))
        {
            return;
        }
        let node = self.span(site);
        self.builder.boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: site.child_by_field_name("function").map(|function| {
                effinterp_proto::CalleeReference {
                    module: "php".to_string(),
                    symbol: text(function, self.src).to_string(),
                }
            }),
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail,
        });
        for d in KNOWN_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(d), CoverageLevel::Partial);
        }
    }
}
