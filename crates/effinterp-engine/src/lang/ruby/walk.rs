//! Live Ruby execution over the effect plan and its control-flow sites.

mod call_application;
mod effect_emission;
mod output_flow;
mod spawn;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance, CoverageLevel, Domain,
    ProvenanceRef, ResourceExpr, Subject,
};
use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::SiteFacts;
use crate::lang::frontend::{FrontendInput, WalkOutcome};
use crate::nest::{Nest, Transition};
use crate::resource_transfer::TransferBinding;
use crate::summary::{bind_positional, contains_unresolved};

use super::call_resolution::unmodeled_ruby_receiver_call;
use super::control::RubySendControl;
use super::file_context::RubyFileContext;
use super::model::{
    self, RubyModelScope, RubyModeledSend, RubyProcDefinition, apply_live_assign, assigned_proc,
    candidate_limit_boundary, effect, env_index_read, env_key, guarded_ruby_children,
    invoked_procs, model, passed_procs, poison_boundary, poisoned_send_reference, push_proc,
    resolve, spawn_of_parts, yielded_argument_sets,
};
use super::module_load::ruby_require_bindings;
use super::resource_bindings::{
    constructor_instance, note_decoded_local, note_remote_body, remove_assignment_bindings,
    store_binding,
};
use super::summary_capture::RubySummaryCapture;
use super::syntax::{
    ruby_ast_children, ruby_constant_last_segment, ruby_constant_path, ruby_parameter_names,
    ruby_top_statements,
};
use super::{DOMAINS, control};

use output_flow::{
    RubyOutputSource, file_read_call, formatted_arguments, prints_to_stdout, ruby_backtick_sources,
    ruby_file_read_sources,
};

/// Walk Ruby module execution and mark declarations only when no callable or effect was reached.
pub(super) fn walk_ruby(
    builder: &mut PlanBuilder,
    nest: &Nest,
    input: &FrontendInput,
    root: &Node,
) -> WalkOutcome {
    let cwd = input.runtime_cwd;
    let cwd_node = input.cwd_node;
    let scope = input.scope;
    let depth = input.depth;
    if builder.current_execution_is_launched_source() {
        for import in ruby_require_bindings(root, nest.resolver.is_some()) {
            if crate::classify_ruby_require(&import.module).is_none() {
                nest.follow_dependency(
                    builder,
                    &import.module,
                    "ruby",
                    crate::nest::dependency_sources::DependencyLoad::Static,
                );
            }
        }
    }
    let mut ctx = RubyFileContext::collect(input.source, root);
    // Launch values describe entry state; source-level mutation invalidates them.
    let mut argv = builder.current_execution_argv();
    if !argv.is_empty() {
        let mut pending = vec![root];
        for _ in 0..nest.limits.max_ruby_nodes {
            let Some(node) = pending.pop() else {
                break;
            };
            let changes_argv = match node {
                Node::Casgn(assignment) => assignment.name == "ARGV",
                Node::IndexAsgn(assignment) => {
                    ruby_constant_path(&assignment.recv).as_deref() == Some("ARGV")
                }
                Node::Send(call) => {
                    call.recv.as_deref().and_then(ruby_constant_path).as_deref() == Some("ARGV")
                }
                _ => false,
            };
            if changes_argv {
                argv = &[];
                break;
            }
            pending.extend(ruby_ast_children(node));
        }
        if !pending.is_empty() {
            argv = &[];
        }
    }
    for (index, value) in argv.iter().skip(2).enumerate() {
        ctx.consts.insert(format!("ARGV[{index}]"), value.clone());
    }
    let declared_callables: Vec<String> = ctx
        .defs
        .iter()
        .filter(|definition| definition.declared)
        .map(|definition| definition.key.clone())
        .collect();

    let first_effect = builder.effects_len();
    let statements = ruby_top_statements(root);
    builder.control_enter(input.source, false, |graph| {
        control::build_ruby_control_flow(graph, &statements, ctx.exception_builtins)
    });
    let mut w = RubyWalker {
        source: input.source,
        builder,
        nest,
        cwd,
        cwd_node,
        scope,
        depth,
        ctx: &ctx,
        env: ctx.consts.clone(),
        vars: HashMap::new(),
        class_refs: HashMap::new(),
        ivars: HashMap::new(),
        instances: HashMap::new(),
        remote_bodies: HashMap::new(),
        decoded_locals: HashSet::new(),
        poisoned: HashSet::new(),
        procs: HashMap::new(),
        active_procs: HashSet::new(),
        captures: HashMap::new(),
        applications: HashMap::new(),
        nodes_left: nest.limits.max_ruby_nodes,
        truncated: false,
        candidate_limit_reported: false,
        call_site_limit_reported: false,
        environment_rewritten: false,
        printed_captures: HashSet::new(),
        printed_reads: HashMap::new(),
        read_effects: HashMap::new(),
        request_bodies: HashMap::new(),
        read_locals: HashMap::new(),
        captured_outputs: HashMap::new(),
        capture_locals: HashMap::new(),
        post_loop_assignments: HashMap::new(),
    };
    for stmt in statements {
        w.stmt(stmt);
    }
    w.builder.control_leave();
    let shadows_thor = ctx.classes.iter().any(|class| class.name == "Thor");
    if !shadows_thor {
        for class in ctx.classes.iter().filter(|class| {
            class
                .bases
                .iter()
                .any(|base| ruby_constant_last_segment(base) == "Thor")
        }) {
            for method in ctx.pub_methods.get(&class.name).into_iter().flatten() {
                w.apply_ruby_command_root(&format!("{}.{}", class.name, method));
            }
        }
    }
    let entered_callables = !w.applications.is_empty();
    drop(w);
    for domain in DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
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

/// Live-plan walker for module execution.
struct RubyWalker<'a> {
    source: &'a str,
    builder: &'a mut PlanBuilder,
    nest: &'a Nest<'a>,
    cwd: Option<&'a str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    ctx: &'a RubyFileContext,
    env: HashMap<String, ResourceExpr>,
    vars: HashMap<String, Vec<String>>,
    class_refs: HashMap<String, String>,
    ivars: HashMap<String, Vec<String>>,
    instances: HashMap<String, HashMap<String, ResourceExpr>>,
    /// Locals holding a web response body, with the endpoint it came from.
    remote_bodies: HashMap<String, ResourceExpr>,
    /// Locals that may hold a decoder's result (`model::decoded`).
    decoded_locals: HashSet<String>,
    poisoned: HashSet<String>,
    procs: HashMap<String, Vec<RubyProcDefinition>>,
    active_procs: HashSet<usize>,
    captures: HashMap<String, Rc<RubySummaryCapture>>,
    applications: HashMap<String, HashSet<String>>,
    nodes_left: u64,
    truncated: bool,
    candidate_limit_reported: bool,
    call_site_limit_reported: bool,
    /// The program wrote `ENV`, so later reads no longer see the host values.
    environment_rewritten: bool,
    /// Backtick spans a later output call prints: they run with the
    /// program's stdout instead of a captured one.
    printed_captures: HashSet<(usize, usize)>,
    /// `File.read`-style call spans an output call prints, and whether it
    /// prints them verbatim (`Exact`) or as `inspect` escapes them
    /// (`Conservative`): the file's bytes reach the program's stdout.
    printed_reads: HashMap<(usize, usize), effinterp_proto::CausalAssurance>,
    /// The read effects each walked `File.read`-style call emitted.
    read_effects: HashMap<(usize, usize), Vec<u32>>,
    /// Requests consuming the bytes of an inline file read, keyed by read span.
    request_bodies: HashMap<(usize, usize), Vec<u32>>,
    /// The `File.read`-style call spans whose bytes each local may hold. A
    /// guarded assignment adds to what the local held; only an unguarded one
    /// replaces it.
    read_locals: HashMap<String, BTreeSet<(usize, usize)>>,
    /// Each captured backtick's child execution and the stdout it would
    /// have inherited, so printing the captured value can reconnect it.
    captured_outputs: HashMap<
        (usize, usize),
        (
            effinterp_proto::ExecutionNodeRef,
            Option<effinterp_proto::ExecutionStreamRef>,
        ),
    >,
    /// Backtick spans whose output a local holds, each with whether the local
    /// holds those bytes verbatim.
    capture_locals: HashMap<String, Vec<RubyOutputSource>>,
    /// Local assignments a reached `begin … end while`/`until` body's first
    /// iteration reaches, by start offset. The body runs at least once, so a
    /// `true` one replaces the output a local held; a `false` one sits in a
    /// rescue or ensure body, so the earlier output may or may not remain.
    /// Later iterations keep them guarded for value resolution.
    post_loop_assignments: HashMap<usize, bool>,
}

impl RubyWalker<'_> {
    fn stmt(&mut self, node: &Node) {
        let depth = self.builder.condition_depth();
        self.stmt_nodes(node);
        while self.builder.condition_depth() > depth {
            self.builder.pop_condition();
        }
    }

    fn stmt_nodes(&mut self, node: &Node) {
        let mut stack = vec![(node, false)];
        let depth = self.builder.condition_depth();
        while let Some((node, guarded)) = stack.pop() {
            while self.builder.condition_depth() > depth {
                self.builder.pop_condition();
            }
            let expression = node.expression();
            if let Some(condition) = self.ctx.guards.at(effinterp_proto::ByteSpan {
                start: expression.begin as u32,
                end: expression.end as u32,
            }) {
                self.builder.push_condition(condition);
            }
            if !crate::nest::charge_analysis_steps(
                self.builder,
                self.nest.budget,
                1,
                Some((expression.begin as u32, expression.end as u32)),
            ) {
                self.truncated = true;
                return;
            }
            if self.nodes_left == 0 {
                if !self.truncated {
                    self.truncated = true;
                    self.builder.boundary(Boundary {
                        reason: BoundaryReason::PARTIAL_ANALYSIS,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                        provenance: self.scope.as_slice().to_vec(),
                        limit: Some("max_ruby_nodes".to_string()),
                        detail: Some("ruby walk node budget exhausted".to_string()),
                    });
                }
                return;
            }
            self.nodes_left -= 1;
            let guarded = guarded || matches!(node, Node::OrAsgn(_) | Node::AndAsgn(_));
            if !guarded
                && let Node::WhilePost(lib_ruby_parser::nodes::WhilePost { body, .. })
                | Node::UntilPost(lib_ruby_parser::nodes::UntilPost { body, .. }) = node
                && let Node::KwBegin(block) = &**body
            {
                first_iteration_assignments(&block.statements, &mut self.post_loop_assignments);
            }
            let control_since = self.builder.control_registered();
            let control_effects = self.builder.effects_len();
            // An array literal's `each` runs its block once per element, as
            // it runs a proc passed with `&`. The block's proc rebindings are
            // left to the walk below, which keeps the earlier procs reachable.
            if let Node::Block(block) = node
                && let Node::Send(call) = &*block.call
                && call.method_name == "each"
                && call.args.is_empty()
                && matches!(call.recv.as_deref(), Some(Node::Array(array)) if !array.elements.is_empty())
                && let Some(body) = block.body.as_deref()
            {
                let proc_def = RubyProcDefinition {
                    params: ruby_parameter_names(&block.args),
                    body: Rc::new(body.clone()),
                };
                let procs = self.procs.clone();
                for args in yielded_argument_sets(call, &self.env, self.cwd) {
                    self.run_proc(&proc_def, &args);
                }
                self.procs = procs;
            }
            match node {
                Node::Send(s) => {
                    if prints_to_stdout(s) {
                        // `p` and `pp` print `inspect`, a quoted rendering of
                        // the text rather than its bytes.
                        let printed = match s.method_name.as_str() {
                            "printf" => formatted_arguments(&s.args),
                            "p" | "pp" => None,
                            _ => Some(s.args.iter().collect()),
                        };
                        let (arguments, assurance) = match &printed {
                            Some(printed) => (printed.clone(), CausalAssurance::Exact),
                            None => (s.args.iter().collect(), CausalAssurance::Conservative),
                        };
                        self.print_reads(&arguments, assurance, s);
                        match printed {
                            Some(printed) => self.print_captures(&printed, true, s),
                            None => {
                                self.print_captures(&s.args.iter().collect::<Vec<_>>(), false, s)
                            }
                        }
                    }
                    let before = self.builder.effects_len();
                    self.send(s);
                    let span = (s.expression_l.begin, s.expression_l.end);
                    if s.method_name == "post"
                        && s.recv.as_deref().and_then(ruby_constant_path).as_deref()
                            == Some("Net::HTTP")
                    {
                        let requests: Vec<_> = (before..self.builder.effects_len())
                            .filter(|slot| {
                                matches!(
                                    self.builder.effect_operation(*slot),
                                    Some("network.request" | "network.upload")
                                )
                            })
                            .map(|slot| slot as u32)
                            .collect();
                        // The body may be a read, a local holding one, or
                        // text built from either.
                        let (inline, locals) = s
                            .args
                            .get(1)
                            .map(ruby_file_read_sources)
                            .unwrap_or_default();
                        for (span, _) in inline {
                            self.request_bodies.insert(span, requests.clone());
                        }
                        for (local, _) in locals {
                            let reads = self
                                .read_locals
                                .get(&local)
                                .into_iter()
                                .flatten()
                                .filter_map(|span| self.read_effects.get(span))
                                .flatten()
                                .copied()
                                .collect::<BTreeSet<_>>();
                            for read in reads {
                                for request in &requests {
                                    self.builder
                                        .transfer_binding(TransferBinding::new(read, *request));
                                }
                            }
                        }
                    }
                    if file_read_call(s) {
                        let reads = (before..self.builder.effects_len())
                            .filter(|effect| {
                                self.builder.effect_operation(*effect) == Some("filesystem.read")
                            })
                            .map(|effect| effect as u32)
                            .collect::<Vec<_>>();
                        if let Some(assurance) = self.printed_reads.get(&span).copied() {
                            self.bind_reads_to_stdout(reads.clone(), assurance, span);
                        }
                        if let Some(requests) = self.request_bodies.remove(&span) {
                            for read in &reads {
                                for request in &requests {
                                    self.builder
                                        .transfer_binding(TransferBinding::new(*read, *request));
                                }
                            }
                        }
                        self.read_effects.insert(span, reads);
                    }
                }
                Node::Index(ix) => {
                    if let Some(e) = env_index_read(ix) {
                        self.emit(e, ix.expression_l.begin, ix.expression_l.end);
                    }
                }
                Node::IndexAsgn(ix) => {
                    if ruby_constant_path(&ix.recv).as_deref() == Some("ENV") {
                        self.emit(
                            effect("environment.write", env_key(&ix.indexes), false),
                            ix.expression_l.begin,
                            ix.expression_l.end,
                        );
                    }
                }
                // Backticks / %x{...} run a shell command, like system().
                Node::Xstr(x) => {
                    let m = spawn_of_parts(&x.parts);
                    let span = (x.expression_l.begin, x.expression_l.end);
                    let captured = !self.printed_captures.contains(&span);
                    self.spawned(m, span.0, span.1, captured);
                }
                Node::XHeredoc(x) => {
                    let m = spawn_of_parts(&x.parts);
                    let span = (x.expression_l.begin, x.expression_l.end);
                    let captured = !self.printed_captures.contains(&span);
                    self.spawned(m, span.0, span.1, captured);
                }
                Node::Lvasgn(_) | Node::Ivasgn(_) | Node::OrAsgn(_) | Node::AndAsgn(_) => {
                    if apply_live_assign(
                        node,
                        &mut self.vars,
                        &mut self.class_refs,
                        &mut self.ivars,
                        None,
                        self.ctx,
                        guarded,
                    ) {
                        self.candidate_limit();
                    }
                    if let Node::Lvasgn(assignment) = node {
                        if let Some(value) = assignment.value.as_deref() {
                            // `y = x` copies the bytes of every read `x` may
                            // hold, as does text built from `x`.
                            let (reads, locals) = ruby_file_read_sources(value);
                            let mut assigned: BTreeSet<_> =
                                reads.into_iter().map(|(span, _)| span).collect();
                            for (local, _) in locals {
                                assigned.extend(self.read_locals.get(&local).into_iter().flatten());
                            }
                            // A guarded assignment may not run, so the
                            // earlier reads may still be what it holds.
                            let mut held = if guarded {
                                self.read_locals
                                    .remove(&assignment.name)
                                    .unwrap_or_default()
                            } else {
                                BTreeSet::new()
                            };
                            held.extend(assigned);
                            if held.is_empty() {
                                self.read_locals.remove(&assignment.name);
                            } else {
                                self.read_locals.insert(assignment.name.clone(), held);
                            }
                            let (mut held, locals) = ruby_backtick_sources(value);
                            for (local, exact) in locals {
                                held.extend(
                                    self.capture_locals
                                        .get(&local)
                                        .into_iter()
                                        .flatten()
                                        .map(|&(span, verbatim)| (span, exact && verbatim)),
                                );
                            }
                            let earlier = self
                                .capture_locals
                                .get(&assignment.name)
                                .cloned()
                                .unwrap_or_default();
                            match self
                                .post_loop_assignments
                                .get(&assignment.expression_l.begin)
                            {
                                Some(true) => {}
                                Some(false) => {
                                    held.extend(earlier.into_iter().map(|(span, _)| (span, false)))
                                }
                                None if guarded => held.extend(earlier),
                                None => {}
                            }
                            self.capture_locals.insert(assignment.name.clone(), held);
                            note_remote_body(
                                &mut self.remote_bodies,
                                &assignment.name,
                                model::remote_body(value, &self.env, self.cwd),
                                guarded,
                            );
                            note_decoded_local(
                                &mut self.decoded_locals,
                                &assignment.name,
                                value,
                                guarded,
                            );
                            let resolved = resolve(value, &self.env, self.cwd);
                            store_binding(
                                &mut self.env,
                                &mut self.poisoned,
                                &assignment.name,
                                resolved,
                                guarded,
                            );
                            if guarded {
                                self.instances.remove(&assignment.name);
                            } else if let Some(instance) =
                                constructor_instance(value, &self.env, self.cwd, None, self.ctx)
                            {
                                self.instances.insert(assignment.name.clone(), instance);
                            } else {
                                self.instances.remove(&assignment.name);
                            }
                        }
                        if !guarded {
                            self.procs.remove(&assignment.name);
                        }
                    }
                    if let Node::Ivasgn(assignment) = node
                        && let Some(value) = assignment.value.as_deref()
                    {
                        let resolved = resolve(value, &self.env, self.cwd);
                        store_binding(
                            &mut self.env,
                            &mut self.poisoned,
                            &assignment.name,
                            resolved,
                            guarded,
                        );
                    }
                    if let Some((name, body)) = assigned_proc(node)
                        && push_proc(&mut self.procs, name, body)
                    {
                        self.candidate_limit();
                    }
                }
                Node::Masgn(assignment) => {
                    remove_assignment_bindings(&assignment.lhs, &mut self.env, &mut self.poisoned);
                }
                Node::OpAsgn(assignment) => {
                    remove_assignment_bindings(&assignment.recv, &mut self.env, &mut self.poisoned);
                }
                _ => {}
            }
            if matches!(
                node,
                Node::Index(_) | Node::IndexAsgn(_) | Node::Xstr(_) | Node::XHeredoc(_)
            ) {
                let facts = SiteFacts::known(
                    self.builder
                        .control_own_effects(control_effects..self.builder.effects_len()),
                );
                self.builder.control_site_since(
                    self.source,
                    false,
                    control::span(node),
                    control_since,
                    facts,
                );
            }
            // Class bodies execute when defined; method bodies execute only
            // when reached through their call edges.
            if assigned_proc(node).is_none() && !matches!(node, Node::Def(_) | Node::Defs(_)) {
                // A literal test selects one arm; the other never runs.
                let literal = match node {
                    Node::If(branch) => control::constant_truth(&branch.cond).map(|truth| {
                        (
                            &branch.cond,
                            if truth {
                                &branch.if_true
                            } else {
                                &branch.if_false
                            },
                        )
                    }),
                    Node::IfMod(branch) => control::constant_truth(&branch.cond).map(|truth| {
                        (
                            &branch.cond,
                            if truth {
                                &branch.if_true
                            } else {
                                &branch.if_false
                            },
                        )
                    }),
                    _ => None,
                };
                if let Some((test, arm)) = literal {
                    if let Some(arm) = arm.as_deref() {
                        stack.push((arm, guarded));
                    }
                    stack.push((test, guarded));
                } else {
                    let guarded = guarded || guarded_ruby_children(node);
                    for child in ruby_ast_children(node).into_iter().rev() {
                        stack.push((child, guarded));
                    }
                }
            }
        }
    }

    /// Evaluate a send and register what it establishes at its site.
    fn send(&mut self, s: &Send) {
        let since = self.builder.control_registered();
        let before = self.builder.effects_len();
        let facts = match self.send_inner(s) {
            RubySendControl::Own(mut facts) => {
                facts.facts = self
                    .builder
                    .control_own_effects(before..self.builder.effects_len());
                facts.throw_facts = facts.facts.clone();
                facts
            }
            RubySendControl::Applied(facts) => facts,
            RubySendControl::Unknown => SiteFacts::unknown(),
        };
        self.builder
            .control_site_since(self.source, false, control::send_span(s), since, facts);
    }

    fn send_inner(&mut self, s: &Send) -> RubySendControl {
        let invoked = invoked_procs(s, &self.procs);
        if !invoked.is_empty() {
            let args: Vec<ResourceExpr> = s
                .args
                .iter()
                .map(|argument| resolve(argument, &self.env, self.cwd))
                .collect();
            for proc_def in invoked {
                self.run_proc(&proc_def, &args);
            }
            return RubySendControl::Unknown;
        }
        let argument_sets = yielded_argument_sets(s, &self.env, self.cwd);
        let passed = passed_procs(s, &self.procs);
        let callbacks = !passed.is_empty();
        for proc_def in passed {
            for args in &argument_sets {
                self.run_proc(&proc_def, args);
            }
        }
        let control = self.send_modeled(s);
        if callbacks {
            // Procs passed along run under the callee's control.
            return control.with_unknown_exit();
        }
        control
    }

    fn send_modeled(&mut self, s: &Send) -> RubySendControl {
        let scope = RubyModelScope {
            env: &self.env,
            cwd: self.cwd,
            class: None,
            ctx: self.ctx,
            vars: &self.vars,
            class_refs: &self.class_refs,
            ivars: &self.ivars,
            remote_bodies: &self.remote_bodies,
            decoded_locals: &self.decoded_locals,
        };
        let begin = s.expression_l.begin;
        let end = s.expression_l.end;
        match model(s, &scope) {
            RubyModeledSend::Effects {
                effects,
                transfers,
                boundary: unknown,
            } => {
                if let Some(name) = poisoned_send_reference(s, &self.poisoned)
                    && let Some(domain) = effects
                        .iter()
                        .find(|effect| contains_unresolved(&effect.resource))
                        .map(|effect| effect.operation.domain().to_string())
                {
                    let mut boundary = poison_boundary(&name, &domain);
                    boundary.provenance = vec![self.span(begin, end)];
                    self.builder.boundary(boundary);
                }
                if let Some(mut boundary) = unknown {
                    boundary.provenance.push(self.span(begin, end));
                    self.builder.boundary(boundary);
                }
                let slots: Vec<Option<u32>> = effects
                    .into_iter()
                    .map(|e| self.emit(e, begin, end))
                    .collect();
                crate::summary::replay_transfers(self.builder, &transfers, &slots);
                RubySendControl::modeled(s)
            }
            RubyModeledSend::LiteralEval(source) => {
                let site = self.span(begin, end);
                self.nest.nest(
                    self.builder,
                    Transition::file(Subject::Source {
                        dialect: None,
                        language: "ruby".to_string(),
                        source,
                        cwd: self.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .source_cwd(self.nest.current_source_cwd().as_deref())
                    .runtime_cwd(self.cwd)
                    .cwd(self.builder.current_execution_cwd(), self.cwd_node),
                    &[site],
                    self.depth,
                );
                // Eval shares locals with its caller; nested analysis does not
                // return updated bindings, so previous values are no longer proof.
                self.env.clear();
                self.vars.clear();
                self.class_refs.clear();
                self.ivars.clear();
                self.instances.clear();
                self.remote_bodies.clear();
                self.decoded_locals.clear();
                self.procs.clear();
                RubySendControl::Unknown
            }
            RubyModeledSend::DecodedEval => {
                let (decode, execution) = model::decoded_eval_effects();
                let slots = [
                    self.emit_applying(decode, begin, end, Some("ruby/base64@v0")),
                    self.emit(execution, begin, end),
                ];
                crate::summary::replay_transfers(
                    self.builder,
                    &[TransferBinding::new(0, 1)],
                    &slots,
                );
                let mut boundary = model::dyn_boundary("eval");
                boundary.provenance.push(self.span(begin, end));
                self.builder.boundary(boundary);
                RubySendControl::Unknown
            }
            RubyModeledSend::RemoteEval(url) => {
                let slots: Vec<Option<u32>> = model::remote_eval_effects(url)
                    .into_iter()
                    .map(|e| self.emit(e, begin, end))
                    .collect();
                crate::summary::replay_transfers(
                    self.builder,
                    &[TransferBinding::new(0, 1)],
                    &slots,
                );
                let mut boundary = model::dyn_boundary("eval");
                boundary.provenance.push(self.span(begin, end));
                self.builder.boundary(boundary);
                RubySendControl::Unknown
            }
            // A require this launch followed by path is composed, not opaque.
            RubyModeledSend::Boundary(_)
                if ruby_require_bindings(&Node::Send(s.clone()), true)
                    .first()
                    .is_some_and(|import| {
                        self.nest.dependency_calls.is_followed(
                            &crate::dependency_calls::DependencyRequestKey {
                                source_cwd: self.nest.current_source_cwd(),
                                language: "ruby",
                                specifier: import.module.clone(),
                            },
                            self.builder.current_dependency_launch(),
                        )
                    }) =>
            {
                RubySendControl::Unknown
            }
            RubyModeledSend::Boundary(mut b) => {
                b.provenance.push(self.span(begin, end));
                self.builder.boundary(b);
                RubySendControl::Unknown
            }
            spawned @ (RubyModeledSend::ShellSpawn { .. }
            | RubyModeledSend::ExecSpawn { .. }
            | RubyModeledSend::SpawnUnresolved(_)) => {
                self.spawned(spawned, begin, end, false);
                RubySendControl::spawn(s)
            }
            RubyModeledSend::Calls(edges) => {
                let mut applied: Vec<Option<SiteFacts>> = edges
                    .iter()
                    .map(|edge| self.apply_same_file_ruby_call(edge, s))
                    .collect();
                match (applied.len(), applied.pop()) {
                    (1, Some(Some(facts))) => RubySendControl::Applied(facts),
                    _ => RubySendControl::Unknown,
                }
            }
            RubyModeledSend::None => {
                if let Some(callee) = unmodeled_ruby_receiver_call(s, self.ctx) {
                    let arguments = model::value_arguments(&s.args, &self.env, self.cwd);
                    let site = self.span(begin, end);
                    if !crate::dependency_calls::apply_global_dependency_call(
                        self.builder,
                        self.nest,
                        "ruby",
                        &callee,
                        &arguments,
                        site,
                    ) {
                        self.unresolved_call(&callee, s);
                    }
                    // A dependency call is still an external call: its control
                    // is not modeled either way.
                    RubySendControl::Unknown
                } else {
                    RubySendControl::builtin(s, self.ctx.exception_builtins)
                }
            }
        }
    }

    fn run_proc(&mut self, proc_def: &RubyProcDefinition, args: &[ResourceExpr]) {
        let key = Rc::as_ptr(&proc_def.body) as usize;
        if !self.active_procs.insert(key) {
            return;
        }
        let mut env = self.env.clone();
        env.extend(bind_positional(&proc_def.params, args));
        let previous = std::mem::replace(&mut self.env, env);
        self.stmt(&proc_def.body);
        self.env = previous;
        self.active_procs.remove(&key);
    }

    fn unresolved_call(&mut self, callee: &str, s: &Send) {
        let node = self.span(s.expression_l.begin, s.expression_l.end);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: Some(effinterp_proto::CalleeReference {
                module: "ruby".to_string(),
                symbol: callee.to_string(),
            }),
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!(
                "call to unmodeled {callee} at {}..{}",
                s.expression_l.begin, s.expression_l.end
            )),
        });
    }

    fn candidate_limit(&mut self) {
        if self.candidate_limit_reported {
            return;
        }
        self.candidate_limit_reported = true;
        let mut boundary = candidate_limit_boundary();
        boundary.provenance = self.scope.as_slice().to_vec();
        self.builder.boundary(boundary);
    }
}

/// Record the local assignments a post-test loop body's first iteration
/// definitely reaches through sequential statements and nested `begin`
/// bodies, and mark those in rescue or ensure bodies as uncertain. A `next`,
/// `break`, `redo` or `return` may skip what follows it, so collection stops
/// there; the return value says whether it did not.
fn first_iteration_assignments(statements: &[Node], out: &mut HashMap<usize, bool>) -> bool {
    for statement in statements {
        match statement {
            Node::KwBegin(block) => {
                if !first_iteration_assignments(&block.statements, out) {
                    return false;
                }
            }
            Node::Rescue(_) | Node::Ensure(_) => {
                let mut stack = vec![statement];
                while let Some(node) = stack.pop() {
                    if let Node::Lvasgn(assignment) = node {
                        out.entry(assignment.expression_l.begin).or_insert(false);
                    }
                    stack.extend(ruby_ast_children(node));
                }
                if leaves_iteration(statement) {
                    return false;
                }
            }
            _ if leaves_iteration(statement) => return false,
            Node::Lvasgn(assignment) => {
                out.insert(assignment.expression_l.begin, true);
            }
            _ => {}
        }
    }
    true
}

fn leaves_iteration(node: &Node) -> bool {
    matches!(
        node,
        Node::Next(_) | Node::Break(_) | Node::Redo(_) | Node::Return(_)
    ) || ruby_ast_children(node).into_iter().any(leaves_iteration)
}
