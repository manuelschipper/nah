//! Shell function call: running a defined function's body for one command.
//! The call binds the arguments as positional parameters, opens a `local`
//! frame, walks the body in the caller's environment, and registers the
//! function's control-flow guarantees at the call site. A saturated walk
//! retains the call under its saturation memo key instead.

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, Domain, Effect, Modality, Operation,
    ResourceExpr,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::control_flow::{ControlExit, Requirements, SiteFacts};
use crate::nest::degrade_nested;
use crate::paths::process_identity_with_cwd;
use crate::shell::function_definition::FnEntry;
use crate::shell::lex::RedirKind;
use crate::shell::parse::Simple;
use crate::shell::referenced_inputs::{
    expanded_referenced_inputs_bounded, referenced_inputs_with_substitutions,
};
use crate::shell::shell_env::{ShellEnv, downgrade_script_set, script_set_names};
use crate::shell::{
    Converted, MAX_SATURATED_COMMAND_HEADS, MAX_SATURATED_FUNCTION_STEPS, MAX_WALK_DEPTH, Shell,
    Termination, jobs,
};
use crate::word::Word;

/// A shell function's guarantees at its call: its attempt reaches what every
/// return reaches, and a successful status adds what every successful return
/// reaches.
pub(super) fn function_call_facts(requirements: &Requirements) -> SiteFacts {
    SiteFacts {
        call_return: false,
        facts: requirements.on_completion.iter().copied().collect(),
        success: requirements.on_success.iter().copied().collect(),
        returns: requirements.succeeds || requirements.fails || requirements.may_return,
        succeeds: requirements.succeeds,
        exit: requirements.may_exit.then_some(ControlExit::Unknown),
        widen: false,
        ..Default::default()
    }
}

impl Shell<'_> {
    /// Walk a previously defined function's body at this call site with the
    /// call's converted arguments as its positional parameters. Cycles
    /// (the name is already on the walk stack) stop without re-entering but
    /// leave the shell's unbounded re-execution as evidence; deep non-cyclic
    /// chains use the shell function bound.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn call_function(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        entry: &FnEntry,
        args: &[Converted],
        call: &Simple,
        persist: bool,
        conditional: bool,
        guarded: bool,
    ) -> (Option<Requirements>, Option<Termination>) {
        let span = call.span;
        if let Some(cycle) = env.active.iter().position(|frame| frame.0 == name) {
            // The body was already walked by the outer call, so only the
            // shell re-entering it is new. Only a cycle crossing a background
            // launch through invariant bodies certifies process growth.
            let node = self.span_node(builder, span);
            let mut attributes = BTreeMap::from([(
                "source".to_string(),
                AttrValue::String("function".to_string()),
            )]);
            if env.background_depth > env.active[cycle].1
                && env.active[cycle..].iter().all(|frame| {
                    jobs::invariant_recursion(&frame.2, &|name| {
                        env.active[cycle..].iter().any(|frame| frame.0 == name)
                    })
                })
            {
                attributes.insert(
                    "process_growth".into(),
                    AttrValue::String("unbounded_background_recursion".into()),
                );
            }
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("process.code_execution"),
                resource: ResourceExpr::Concrete {
                    identity: process_identity_with_cwd(
                        &[Word::literal("sh")],
                        env.cwd_resource.clone(),
                    ),
                },
                attributes,
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![node],
            });
            degrade_nested(builder);
            builder.boundary(Boundary {
                reason: BoundaryReason::EXECUTION_CYCLE,
                class: BoundaryClass::Limit,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(format!("shell function {name:?} re-entered while active")),
            });
            return (None, None);
        }
        if env.active.len() as u64 >= self.nest.limits.max_shell_function_depth {
            if self.nest.budget.note_function_depth_saturated() {
                let node = self.span_node(builder, span);
                degrade_nested(builder);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![node],
                    limit: Some("max_shell_function_depth".to_string()),
                    detail: None,
                });
            }
            return (None, None);
        }
        // Spans in the body are relative to the definition's source, which
        // may differ from this call site (e.g. a substitution inheriting
        // functions from the surrounding script).
        let callee = Shell {
            nest: self.nest,
            source: entry.source.as_ref(),
            source_digest: Rc::clone(&entry.source_digest),
            scope: entry.scope,
            depth: self.depth,
        };
        let saved_redirs = env.redirections.clone();
        let saved_sockets = env.socket_fds.clone();
        // `f >dest` opens dest before the body runs, so the body's commands
        // write through it, as they do through the definition's own
        // redirections, which apply after the call's. Here-documents keep
        // their bytes in the calling command, which opens them afterwards.
        let mut redirected = Vec::new();
        // Held out of the environment while the body runs, so a nested call's
        // own redirections cannot take its place; restored on every return.
        let mut call_slot = None;
        if !call.redirs.is_empty()
            && call
                .redirs
                .iter()
                .all(|redir| !matches!(redir.kind, RedirKind::HereDoc | RedirKind::HereString))
        {
            let reuse = env
                .call_redirects
                .as_ref()
                .filter(|(source, at, _)| *at == span && Rc::ptr_eq(source, &self.source_digest))
                .map(|(_, _, redirects)| redirects.clone());
            let redirects = reuse.unwrap_or_else(|| {
                let effect_start = builder.effects_len();
                self.redirects(
                    builder,
                    env,
                    call,
                    false,
                    persist,
                    conditional,
                    guarded,
                    &HashMap::new(),
                    None,
                    effect_start,
                )
            });
            env.redirections.extend(redirects.flows.clone());
            redirected.extend(redirects.flows.clone());
            call_slot = Some((Rc::clone(&self.source_digest), span, redirects));
        }
        redirected.extend(if entry.redirs.is_empty() {
            Vec::new()
        } else {
            let command = Simple {
                assignments: Vec::new(),
                words: Vec::new(),
                redirs: entry.redirs.clone(),
                compound_redirects: false,
                span,
            };
            let effect_start = builder.effects_len();
            let redirects = callee.redirects(
                builder,
                env,
                &command,
                false,
                false,
                conditional,
                false,
                &HashMap::new(),
                None,
                effect_start,
            );
            env.redirections.extend(redirects.flows.clone());
            redirects.flows
        });
        let mut termination = None;
        let functions = crate::shell::function_definition::defined_functions(&entry.body, env);
        builder.control_enter(entry.source.as_ref(), false, |graph| {
            crate::shell::control::build(
                graph,
                entry.source.as_ref(),
                &entry.body,
                crate::shell::control::Callable::Function,
                &|name| functions.contains(name),
            )
        });
        if persist {
            let previous_source =
                std::mem::replace(&mut env.script_source, entry.source_origin.clone());
            env.active.push((
                name.to_string(),
                env.background_depth,
                Rc::clone(&entry.body),
            ));
            env.local_frames.push(HashMap::new());
            env.attribute_frames.push(HashMap::new());
            let saved = env.positional.replace(args.to_vec());
            let saved_changed = env.positional_set_changed;
            env.positional_set_changed = Some(false);
            let saved_aliases = std::mem::replace(&mut env.aliases, entry.aliases.clone());
            let saved_expand_aliases =
                std::mem::replace(&mut env.expand_aliases, entry.expand_aliases);
            if conditional {
                // The whole call is a may-region: names its body assigns
                // stop suppressing environment reads once it returns.
                let before = script_set_names(env);
                let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.source_digest.as_ref(), span.start, span.end),
                ));
                termination = callee.walk(builder, env, &entry.body, true, 0);
                builder.leave_condition_call(previous_call);
                downgrade_script_set(env, &before);
            } else {
                let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.source_digest.as_ref(), span.start, span.end),
                ));
                termination = callee.walk(builder, env, &entry.body, false, 0);
                builder.leave_condition_call(previous_call);
            }
            // Aliases the body defined or enabled persist in the caller.
            for (alias, definition) in std::mem::replace(&mut env.aliases, saved_aliases) {
                if entry.aliases.get(&alias) != Some(&definition) {
                    env.aliases.insert(alias, definition);
                }
            }
            if env.expand_aliases == entry.expand_aliases {
                env.expand_aliases = saved_expand_aliases;
            }
            for (name, attributes) in env.attribute_frames.pop().unwrap() {
                match attributes {
                    Some(attributes) => env.value_attributes.insert(name, attributes),
                    None => env.value_attributes.remove(&name),
                };
            }
            for (name, (scalar, array)) in env.local_frames.pop().unwrap() {
                match scalar {
                    Some(entry) => {
                        env.vars.insert(name.clone(), entry);
                    }
                    None => {
                        env.vars.remove(&name);
                    }
                }
                match array {
                    Some(value) => {
                        env.arrays.insert(name, value);
                    }
                    None => {
                        env.arrays.remove(&name);
                    }
                }
            }
            env.positional = saved;
            env.positional_set_changed = if conditional && saved_changed != Some(false) {
                None
            } else {
                Some(false)
            };
            env.active.pop();
            env.script_source = previous_source;
        } else {
            let referenced_inputs = if env.function_heads_only {
                let mut memos = env.saturation_memos.borrow_mut();
                if memos.function_env_clones >= MAX_SATURATED_COMMAND_HEADS {
                    env.redirections = saved_redirs;
                    env.socket_fds = saved_sockets;
                    builder.control_leave();
                    if call_slot.is_some() {
                        env.call_redirects = call_slot;
                    }
                    return (None, None);
                }
                memos.function_env_clones += 1;
                let refs = entry.saturated_inputs.get_or_init(|| {
                    referenced_inputs_with_substitutions(
                        &entry.body,
                        self.nest
                            .limits
                            .max_execution_depth
                            .min(MAX_WALK_DEPTH as u64) as u32,
                    )
                });
                let Some((variables, functions, work)) = expanded_referenced_inputs_bounded(
                    &refs.vars,
                    &refs.calls,
                    &refs.command_vars,
                    &refs.command_head_patterns,
                    env,
                    self.nest
                        .limits
                        .max_shell_function_depth
                        .saturating_sub(env.active.len() as u64 + 1),
                    MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_steps),
                ) else {
                    memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
                    drop(memos);
                    env.redirections = saved_redirs;
                    env.socket_fds = saved_sockets;
                    builder.control_leave();
                    if call_slot.is_some() {
                        env.call_redirects = call_slot;
                    }
                    return (None, None);
                };
                memos.function_steps += work;
                Some((variables, functions))
            } else {
                None
            };
            let mut child = match &referenced_inputs {
                Some((variables, functions)) => self.child_env_with_inputs(
                    env,
                    Some(variables),
                    Some(functions),
                    Some(args.to_vec()),
                ),
                None => self.child_env(env),
            };
            // A function runs in the caller's process.
            child.pid_is_own = env.pid_is_own;
            child.script_source = entry.source_origin.clone();
            child.aliases = entry.aliases.clone();
            child.expand_aliases = entry.expand_aliases;
            child.active.push((
                name.to_string(),
                child.background_depth,
                Rc::clone(&entry.body),
            ));
            child.positional_set_changed = Some(false);
            if referenced_inputs.is_none() {
                child.positional = Some(args.to_vec());
            }
            let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(self.source_digest.as_ref(), span.start, span.end),
            ));
            callee.walk(builder, &mut child, &entry.body, conditional, 0);
            builder.leave_condition_call(previous_call);
        }
        if !redirected.is_empty() {
            env.redirections
                .extend(crate::flow::restore_descriptors(&saved_redirs, &redirected));
            for redir in &redirected {
                if let Some(socket) = saved_sockets.get(&redir.fd) {
                    env.socket_fds.insert(redir.fd, socket.clone());
                } else {
                    env.socket_fds.remove(&redir.fd);
                }
            }
        }
        if call_slot.is_some() {
            env.call_redirects = call_slot;
        }
        let requirements = builder
            .control_leave()
            .map(|finished| finished.requirements);
        (
            requirements,
            termination
                .map(|(kind, _)| kind)
                .filter(|kind| *kind != Termination::Return),
        )
    }
}
