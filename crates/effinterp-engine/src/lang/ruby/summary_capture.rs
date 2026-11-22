use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, ResourceExpr,
};
use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::SemanticValue;
use crate::builder::KNOWN_DOMAINS;
use crate::control_flow::{ControlExit, ControlFact, ControlStack, Requirements, SiteFacts};
use crate::limits::DEFAULT_MAX_RUBY_NODES;
use crate::module_summary::CallEdge;
use crate::resource_transfer::TransferBinding;
use crate::summary::{
    bind_positional, contains_unresolved, has_text_concat, substitute_resource_expr,
};

use super::call_resolution::{resolve_same_file_ruby_call, unmodeled_ruby_receiver_call};
use super::control::RubySendControl;
use super::file_context::RubyFileContext;
use super::model::{
    self, RubyModelScope, RubyModeledSend, RubyProcDefinition, apply_live_assign, assigned_proc,
    candidate_limit_boundary, constant_env, effect, env_index_read, env_key, guarded_ruby_children,
    invoked_procs, model, network_sink, passed_procs, poison_boundary, poisoned_send_reference,
    push_proc, resolve, spawn_of_parts, yielded_argument_sets,
};
use super::resource_bindings::{
    bind_ruby_call_resources, constructor_instance, instance_bindings, note_decoded_local,
    note_remote_body, remove_assignment_bindings, store_binding, unresolved_instance_parameters,
};
use super::spawn_resources::substitute_ruby_spawn;
use super::syntax::{ruby_ast_children, ruby_constant_path, ruby_top_statements};
use super::{DOMAINS, MAX_INLINE_DEPTH, control};

/// Registrations of summary walks share one frame key per capture stack.
static CAPTURE_SOURCE: &str = "ruby capture";

/// Effects/boundaries/calls captured while summarizing a method body.
#[derive(Clone, Default)]
pub(super) struct RubySummaryCapture {
    pub(super) effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    pub(super) transfers: Vec<TransferBinding>,
    pub(super) boundaries: Vec<Boundary>,
    pub(super) calls: Vec<CallEdge>,
    pub(super) spawns: Vec<(RubyModeledSend, Option<effinterp_proto::Condition>)>,
    /// What the body guarantees over `effects` slots, when it was walked.
    pub(super) control: Option<Requirements>,
    pub(super) control_flow: crate::control_flow::ControlFlow,
}

/// Capture a Ruby summary with symbolic parameters and private effect slots.
pub(super) fn capture_ruby_summary(
    body: Option<&Node>,
    params: &[String],
    class: Option<&str>,
    ctx: &RubyFileContext,
) -> RubySummaryCapture {
    let _walk = crate::limits::summary_walk();
    let mut cap = RubySummaryCapture::default();
    let Some(node) = body else {
        return cap;
    };
    let mut env = constant_env(ctx, class);
    env.extend(
        params
            .iter()
            .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() })),
    );
    if let Some(class) = class {
        env.extend(class_ivar_names(ctx, class).into_iter().map(|name| {
            let parameter = format!("@{name}");
            (
                parameter.clone(),
                ResourceExpr::Parameter { name: parameter },
            )
        }));
    }
    let mut stack = Vec::new();
    let mut nodes_left = crate::limits::invocation_node_limit(DEFAULT_MAX_RUBY_NODES);
    let mut control = ControlStack::default();
    capture_into(
        node,
        &env,
        class,
        ctx,
        &mut stack,
        &mut nodes_left,
        &mut control,
        &mut cap,
    );
    cap
}

/// Capture a body into `cap`, sharing the inline stack and node budget with
/// the enclosing capture so recursive same-file inlining terminates.
#[allow(clippy::too_many_arguments)]
fn capture_into(
    body: &Node,
    env: &HashMap<String, ResourceExpr>,
    class: Option<&str>,
    ctx: &RubyFileContext,
    stack: &mut Vec<String>,
    nodes_left: &mut u64,
    control: &mut ControlStack,
    cap: &mut RubySummaryCapture,
) {
    let statements = ruby_top_statements(body);
    control.enter(
        CAPTURE_SOURCE,
        true,
        Default::default(),
        0,
        0,
        None,
        control::summary_caps(),
        |graph| control::build_ruby_control_flow(graph, &statements, ctx.exception_builtins),
    );
    let mut c = RubySummaryWalker {
        cap,
        env: env.clone(),
        class,
        ctx,
        vars: HashMap::new(),
        class_refs: HashMap::new(),
        ivars: HashMap::new(),
        instances: HashMap::new(),
        remote_bodies: HashMap::new(),
        decoded_locals: HashSet::new(),
        poisoned: HashSet::new(),
        procs: HashMap::new(),
        active_procs: HashSet::new(),
        stack,
        nodes_left,
        control,
    };
    for stmt in statements {
        c.stmt(stmt);
    }
    let exhausted = *c.nodes_left == 0;
    let finished = c.control.leave(0);
    if let Some(finished) = finished.filter(|_| !exhausted) {
        cap.control = Some(finished.requirements);
        cap.control_flow = finished.flow;
    } else {
        cap.control = None;
        cap.control_flow = crate::control_flow::ControlFlow::widened();
    }
}

/// Collect a body's parameterized effects and edges in summary slots.
struct RubySummaryWalker<'a> {
    cap: &'a mut RubySummaryCapture,
    env: HashMap<String, ResourceExpr>,
    class: Option<&'a str>,
    ctx: &'a RubyFileContext,
    /// Locals typed by a direct constructor (`x = Cls.new(...)`).
    vars: HashMap<String, Vec<String>>,
    /// Locals bound to a class (`engine_class = Foo::Bar`).
    class_refs: HashMap<String, String>,
    /// Instance variables typed in this body (`@engine ||= ...`).
    ivars: HashMap<String, Vec<String>>,
    instances: HashMap<String, HashMap<String, ResourceExpr>>,
    /// Locals holding a web response body, with the endpoint it came from.
    remote_bodies: HashMap<String, ResourceExpr>,
    /// Locals that may hold a decoder's result (`model::decoded`).
    decoded_locals: HashSet<String>,
    poisoned: HashSet<String>,
    /// Deferred `proc`/`lambda` bodies keyed by their local binding.
    procs: HashMap<String, Vec<RubyProcDefinition>>,
    active_procs: HashSet<usize>,
    stack: &'a mut Vec<String>,
    nodes_left: &'a mut u64,
    pub(super) control: &'a mut ControlStack,
}

impl RubySummaryWalker<'_> {
    fn stmt(&mut self, node: &Node) {
        // Iterative: left-deep `+` / `&&` / Send spines overflow the process
        // stack before the node cap can fire.
        let mut stack = vec![(node, false)];
        while let Some((node, guarded)) = stack.pop() {
            if *self.nodes_left == 0 || !crate::limits::summary_step() {
                self.control.widen();
                if !self
                    .cap
                    .boundaries
                    .iter()
                    .any(|b| b.reason.as_str() == "partial_analysis")
                {
                    self.cap.boundaries.push(Boundary {
                        reason: BoundaryReason::PARTIAL_ANALYSIS,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                        provenance: Vec::new(),
                        limit: Some("max_ruby_nodes".to_string()),
                        detail: Some("ruby summary walk node budget exhausted".to_string()),
                    });
                }
                return;
            }
            *self.nodes_left -= 1;
            let guarded = guarded || matches!(node, Node::OrAsgn(_) | Node::AndAsgn(_));
            let effect_start = self.cap.effects.len();
            let call_start = self.cap.calls.len();
            let spawn_start = self.cap.spawns.len();
            let control_since = self.control.registered();
            match node {
                Node::Send(s) => self.send(s),
                Node::Index(ix) => {
                    if let Some(e) = env_index_read(ix) {
                        self.cap.effects.push(e);
                    }
                }
                Node::IndexAsgn(ix) => {
                    if ruby_constant_path(&ix.recv).as_deref() == Some("ENV") {
                        self.cap.effects.push(effect(
                            "environment.write",
                            env_key(&ix.indexes),
                            false,
                        ));
                    }
                }
                // Backticks / %x{...} / heredoc backticks run a shell command.
                Node::Xstr(x) => self.spawned(spawn_of_parts(&x.parts)),
                Node::XHeredoc(x) => self.spawned(spawn_of_parts(&x.parts)),
                Node::Lvasgn(_) | Node::Ivasgn(_) | Node::OrAsgn(_) | Node::AndAsgn(_) => {
                    if self.note_assign(node, guarded) {
                        self.candidate_limit();
                    }
                    if let Node::Lvasgn(assignment) = node {
                        if let Some(value) = assignment.value.as_deref() {
                            note_remote_body(
                                &mut self.remote_bodies,
                                &assignment.name,
                                model::remote_body(value, &self.env, None),
                                guarded,
                            );
                            note_decoded_local(
                                &mut self.decoded_locals,
                                &assignment.name,
                                value,
                                guarded,
                            );
                            let resolved = resolve(value, &self.env, None);
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
                                constructor_instance(value, &self.env, None, self.class, self.ctx)
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
                        let resolved = resolve(value, &self.env, None);
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
                    (effect_start..self.cap.effects.len())
                        .map(|slot| ControlFact::Effect(slot as u32))
                        .collect(),
                );
                self.control.register_since(
                    CAPTURE_SOURCE,
                    true,
                    control::span(node),
                    control_since,
                    facts,
                );
            }
            // Class bodies execute here; methods are summarized separately.
            let range = node.expression();
            let guard = self.ctx.guards.at(effinterp_proto::ByteSpan {
                start: range.begin as u32,
                end: range.end as u32,
            });
            for effect in &mut self.cap.effects[effect_start..] {
                effect.condition = effinterp_proto::Condition::compose(
                    effect.condition.iter().chain(guard.iter()),
                );
            }
            for (_, condition) in &mut self.cap.spawns[spawn_start..] {
                *condition =
                    effinterp_proto::Condition::compose(condition.iter().chain(guard.iter()));
            }
            for edge in &mut self.cap.calls[call_start..] {
                edge.condition =
                    effinterp_proto::Condition::compose(edge.condition.iter().chain(guard.iter()));
                if edge.call_site.is_none() {
                    edge.call_site = Some(effinterp_proto::stable_hash(
                        effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                        &(&self.ctx.source_digest, range.begin, range.end),
                    ));
                }
            }
            if assigned_proc(node).is_none() && !matches!(node, Node::Def(_) | Node::Defs(_)) {
                let guarded = guarded || guarded_ruby_children(node);
                for child in ruby_ast_children(node).into_iter().rev() {
                    stack.push((child, guarded));
                }
            }
        }
    }

    fn send(&mut self, s: &Send) {
        let since = self.control.registered();
        let before = self.cap.effects.len();
        let calls = self.cap.calls.len();
        let mut facts = match self.send_inner(s) {
            RubySendControl::Own(mut facts) => {
                facts.facts = (before..self.cap.effects.len())
                    .map(|slot| ControlFact::Effect(slot as u32))
                    .collect();
                facts.throw_facts = facts.facts.clone();
                facts
            }
            RubySendControl::Applied(facts) => facts,
            RubySendControl::Unknown => SiteFacts::unknown(),
        };
        if s.recv.is_none()
            && matches!(
                s.method_name.as_str(),
                "require" | "require_relative" | "load"
            )
        {
            facts.exit = Some(match s.args.first() {
                Some(Node::Str(literal)) => {
                    let mut module = literal.value.to_string_lossy();
                    if matches!(s.method_name.as_str(), "require_relative" | "load")
                        && !module.starts_with("./")
                        && !module.starts_with("../")
                        && !module.starts_with('/')
                    {
                        module = format!("./{module}");
                    }
                    ControlExit::Import { module }
                }
                _ => ControlExit::Unknown,
            });
            facts.call_return = false;
        }
        // Multiple edges at one send are dispatch alternatives, not several
        // calls that every completion reaches.
        if self.cap.calls.len() == calls + 1 {
            facts.facts.push(ControlFact::Call(calls as u32));
            facts.throw_facts.push(ControlFact::Call(calls as u32));
        }
        self.control
            .register_since(CAPTURE_SOURCE, true, control::send_span(s), since, facts);
    }

    fn send_inner(&mut self, s: &Send) -> RubySendControl {
        let invoked = invoked_procs(s, &self.procs);
        if !invoked.is_empty() {
            let args: Vec<ResourceExpr> = s
                .args
                .iter()
                .map(|argument| resolve(argument, &self.env, None))
                .collect();
            for proc_def in invoked {
                self.run_proc(&proc_def, &args);
            }
            return RubySendControl::Unknown;
        }
        let argument_sets = yielded_argument_sets(s, &self.env, None);
        let passed = passed_procs(s, &self.procs);
        let callbacks = !passed.is_empty();
        for proc_def in passed {
            for args in &argument_sets {
                self.run_proc(&proc_def, args);
            }
        }
        let control = self.send_modeled(s);
        if callbacks {
            return control.with_unknown_exit();
        }
        control
    }

    fn send_modeled(&mut self, s: &Send) -> RubySendControl {
        let scope = RubyModelScope {
            env: &self.env,
            cwd: None,
            class: self.class,
            ctx: self.ctx,
            vars: &self.vars,
            class_refs: &self.class_refs,
            ivars: &self.ivars,
            remote_bodies: &self.remote_bodies,
            decoded_locals: &self.decoded_locals,
        };
        match model(s, &scope) {
            RubyModeledSend::Effects {
                effects,
                transfers,
                boundary,
            } => {
                if let Some(name) = poisoned_send_reference(s, &self.poisoned)
                    && let Some(domain) = effects
                        .iter()
                        .find(|effect| contains_unresolved(&effect.resource))
                        .map(|effect| effect.operation.domain().to_string())
                {
                    self.cap.boundaries.push(poison_boundary(&name, &domain));
                }
                self.cap.boundaries.extend(boundary);
                let base = self.cap.effects.len() as u32;
                self.cap.effects.extend(effects);
                self.cap
                    .transfers
                    .extend(transfers.into_iter().map(|binding| binding.shifted(base)));
                RubySendControl::modeled(s)
            }
            RubyModeledSend::LiteralEval(_) => {
                // Captures cannot transfer the eval lexical scope to a nested source.
                self.cap.boundaries.push(model::dyn_boundary("eval"));
                RubySendControl::Unknown
            }
            RubyModeledSend::RemoteEval(url) => {
                let base = self.cap.effects.len() as u32;
                self.cap.effects.extend(model::remote_eval_effects(url));
                self.cap
                    .transfers
                    .push(TransferBinding::new(base, base + 1));
                self.cap.boundaries.push(model::dyn_boundary("eval"));
                RubySendControl::Unknown
            }
            RubyModeledSend::DecodedEval => {
                let base = self.cap.effects.len() as u32;
                let (decode, execution) = model::decoded_eval_effects();
                self.cap.effects.extend([decode, execution]);
                self.cap
                    .transfers
                    .push(TransferBinding::new(base, base + 1));
                self.cap.boundaries.push(model::dyn_boundary("eval"));
                RubySendControl::Unknown
            }
            RubyModeledSend::Boundary(b) => {
                self.cap.boundaries.push(b);
                RubySendControl::Unknown
            }
            spawned @ (RubyModeledSend::ShellSpawn { .. }
            | RubyModeledSend::ExecSpawn { .. }
            | RubyModeledSend::SpawnUnresolved(_)) => {
                self.spawned(spawned);
                // The launched command's occurrences are not summary slots.
                match RubySendControl::spawn(s) {
                    RubySendControl::Own(facts) => RubySendControl::Applied(facts),
                    other => other,
                }
            }
            RubyModeledSend::Calls(edges) => {
                let mut applied = Vec::with_capacity(edges.len());
                for edge in edges {
                    applied.push(self.inline_local(&edge, s));
                    self.cap.calls.push(edge);
                }
                match (applied.len(), applied.pop()) {
                    (1, Some(Some(facts))) => RubySendControl::Applied(facts),
                    (1, Some(None)) => RubySendControl::Applied(SiteFacts {
                        call_return: true,
                        ..SiteFacts::unknown()
                    }),
                    _ => RubySendControl::Unknown,
                }
            }
            RubyModeledSend::None => {
                if let Some(callee) = unmodeled_ruby_receiver_call(s, self.ctx) {
                    self.cap.boundaries.push(Boundary {
                        reason: BoundaryReason::UNRESOLVED_CALL,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: Some(effinterp_proto::CalleeReference {
                            module: "ruby".to_string(),
                            symbol: callee.clone(),
                        }),
                        domains: KNOWN_DOMAINS
                            .iter()
                            .map(|domain| Domain::new(*domain))
                            .collect(),
                        provenance: Vec::new(),
                        limit: None,
                        detail: Some(format!(
                            "call to unmodeled {callee} at {}..{}",
                            s.expression_l.begin, s.expression_l.end
                        )),
                    });
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

    /// A subprocess inside a summarized method: recorded as a process.exec
    /// effect on the summary (the nested command is not composed here — the
    /// executable name is kept when statically known).
    fn spawned(&mut self, m: RubyModeledSend) {
        if matches!(
            m,
            RubyModeledSend::ShellSpawn { .. }
                | RubyModeledSend::ExecSpawn { .. }
                | RubyModeledSend::SpawnUnresolved(_)
        ) {
            self.cap.spawns.push((m, None));
        }
    }

    /// Fold a same-file callee's (substituted) effects into this summary, so
    /// a method's summary is self-contained. Cross-file edges are left to the
    /// repository composer, which skips effect collection for same-file
    /// dispatch precisely because of this inlining.
    /// Returns the callee's guarantees over this summary's slots.
    fn inline_local(&mut self, edge: &CallEdge, send: &Send) -> Option<SiteFacts> {
        let def_key = resolve_same_file_ruby_call(self.ctx, edge)?;
        if self.stack.len() >= MAX_INLINE_DEPTH || self.stack.contains(&def_key) {
            return None;
        }
        let (params, defaults, keywords, body, class) = {
            let d = self
                .ctx
                .method_definition(&def_key)
                .expect("local_key checked");
            (
                d.params.clone(),
                d.defaults.clone(),
                d.keywords.clone(),
                d.body.clone(),
                d.class.clone(),
            )
        };
        let body = body?;
        self.stack.push(def_key);
        let mut bindings = bind_ruby_call_resources(&params, &keywords, &edge.arguments);
        for (name, default) in defaults {
            if let std::collections::hash_map::Entry::Vacant(e) = bindings.entry(name) {
                self.stmt(&default);
                e.insert(resolve(&default, &self.env, None));
            }
        }
        bindings.extend(instance_bindings(
            send,
            &self.instances,
            &self.env,
            None,
            self.class,
            self.ctx,
        ));
        let mut inner = RubySummaryCapture::default();
        let mut inner_env = constant_env(self.ctx, class.as_deref());
        inner_env.extend(
            params
                .iter()
                .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() })),
        );
        if let Some(class) = class.as_deref() {
            inner_env.extend(class_ivar_names(self.ctx, class).into_iter().map(|name| {
                let parameter = format!("@{name}");
                (
                    parameter.clone(),
                    ResourceExpr::Parameter { name: parameter },
                )
            }));
        }
        capture_into(
            &body,
            &inner_env,
            class.as_deref(),
            self.ctx,
            self.stack,
            self.nodes_left,
            self.control,
            &mut inner,
        );
        self.stack.pop();
        let base = self.cap.effects.len() as u32;
        let applied = inner.control.as_ref().map(|requirements| {
            SiteFacts::call(requirements, |fact| match fact {
                ControlFact::Effect(index) => Some(ControlFact::Effect(base + index)),
                ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
            })
        });
        for mut e in inner.effects {
            e.resource = substitute_resource_expr(&e.resource, &bindings);
            unresolved_instance_parameters(&mut e.resource);
            if e.operation.domain() == "network" {
                e.resource = network_sink(e.resource);
            }
            if !has_text_concat(&e.resource) {
                let value = SemanticValue::from(&e.resource);
                crate::lower_effect_value(&mut e, &value);
            }
            if let Some(condition) = &mut e.condition {
                condition.rebind(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(
                        &self.ctx.source_digest,
                        send.expression_l.begin,
                        send.expression_l.end,
                    ),
                ));
            }
            self.cap.effects.push(e);
        }
        self.cap.transfers.extend(
            inner
                .transfers
                .into_iter()
                .map(|binding| binding.shifted(base)),
        );
        self.cap.boundaries.extend(inner.boundaries);
        for (spawn, mut condition) in inner.spawns {
            if let Some(condition) = &mut condition {
                condition.rebind(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(
                        &self.ctx.source_digest,
                        send.expression_l.begin,
                        send.expression_l.end,
                    ),
                ));
            }
            self.cap
                .spawns
                .push((substitute_ruby_spawn(spawn, &bindings), condition));
        }
        applied
    }

    fn note_assign(&mut self, node: &Node, guarded: bool) -> bool {
        apply_live_assign(
            node,
            &mut self.vars,
            &mut self.class_refs,
            &mut self.ivars,
            self.class,
            self.ctx,
            guarded,
        )
    }

    fn candidate_limit(&mut self) {
        if !self.cap.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "dynamic_dispatch"
                && boundary.limit.as_deref() == Some("max_callback_values")
        }) {
            self.cap.boundaries.push(candidate_limit_boundary());
        }
    }
}

fn class_ivar_names(ctx: &RubyFileContext, class: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    if let Some(definition) = ctx.method_definition(&format!("{class}.initialize"))
        && let Some(body) = &definition.body
    {
        let mut stack = vec![body.as_ref()];
        while let Some(node) = stack.pop() {
            if let Node::Ivasgn(assignment) = node {
                names.insert(assignment.name.trim_start_matches('@').to_string());
            }
            if !matches!(
                node,
                Node::Def(_) | Node::Defs(_) | Node::Class(_) | Node::SClass(_)
            ) {
                stack.extend(ruby_ast_children(node));
            }
        }
    }
    names
}
