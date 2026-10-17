//! Python summary application: applies a called function's summary at a call
//! site. Resolves the call's arguments in the caller's scope, binds them to the
//! callee's parameters and emits, or in capture mode collects, the specialized
//! effects.

use effinterp_proto::{
    BoundaryReason, PathPlatform, ProvenanceKind, ResourceExpr, normalize_resource,
};
use rustpython_parser::ast::{self, Expr, Ranged};
use rustpython_parser::text_size::TextRange;

use crate::control_flow::{ControlFact, SiteFacts};
use crate::paths::{fs_resource_uses_cwd, resolve_fs_path};
use crate::summary::substitute_resource_expr;
use crate::{SemanticValue, SemanticValueKind, ValueArgument, bind_arguments, substitute_value};

use super::{
    CallReturn, MAX_SUMMARY_EFFECTS, PythonBoundArgument, PythonWalker, ReturnSite, call_arguments,
    python_call_argument, python_plugin_path_pattern,
};

impl PythonWalker<'_, '_> {
    /// Apply a called function's summary at a call site: resolve the actual
    /// arguments in the caller's scope, bind them to the callee's parameters,
    /// and emit (or, in capture mode, collect) the specialized effects.
    pub(super) fn apply_local(&mut self, name: &str, call: &ast::ExprCall, span: TextRange) {
        self.ensure_summary(name);
        let mut bindings = self.call_bindings(name, call);
        if let Expr::Call(producer_call) = call.func.as_ref()
            && let Some(producer) = self.local_callee(&producer_call.func)
        {
            let mut captures = self.call_bindings(&producer, producer_call);
            captures.extend(bindings);
            bindings = captures;
        }
        self.applied_param_flows.clear();
        self.applied_writes.clear();
        self.local_calls_applied += 1;
        self.apply_summary(name, &bindings, span);
        self.bind_param_flows(name, call);
        // The arguments are walked after the call, so its writes wait
        // until they are: for `flow_call` on the plan, and for the call
        // statement in a summarized body. Any other call in a summarized
        // body binds them now, from what the locals its arguments name hold.
        let writes = std::mem::take(&mut self.applied_writes);
        if self.capture.is_none() || self.discarded_call == Some(call.range) {
            self.pending_writes =
                (!writes.is_empty()).then(|| (call.range, name.to_string(), writes));
        } else {
            let walked = self
                .capture
                .as_ref()
                .map_or(0, |capture| capture.effects.len());
            self.capture_writes(name, call, writes, walked);
        }
        self.each_given(|walker| walker.apply_environment(name, call, span));
        let wrappers: Vec<_> = self
            .defs
            .iter()
            .find(|def| def.name == name)
            .into_iter()
            .flat_map(|def| &def.decorators)
            .filter(|decorator| !self.decorator_is_transparent(decorator))
            .filter_map(|decorator| {
                self.defs
                    .iter()
                    .find(|def| def.name == decorator.trim_end_matches("()"))
            })
            .filter_map(|decorator| self.returned_inner(decorator))
            .filter(|(wrapper, _, _)| !wrapper.is_async && !wrapper.is_generator)
            .map(|(wrapper, _, _)| wrapper.name.clone())
            .collect();
        for wrapper in wrappers {
            // An opaque wrapper need not preserve the decorated signature.
            self.apply_local_arguments(&wrapper, &[], span);
        }
        let Some(def) = self.defs.iter().find(|def| def.name == name) else {
            return;
        };
        let writes = def.parameter_attr_writes.clone();
        let params = def.params.clone();
        let positional_param_count = def.positional_param_count;
        let caller_params = self
            .current_function
            .as_deref()
            .and_then(|name| self.defs.iter().find(|def| def.name == name))
            .map(|def| def.params.clone())
            .unwrap_or_default();
        for (param, attr) in writes {
            let Some(index) = params.iter().position(|candidate| candidate == &param) else {
                continue;
            };
            let argument = if index < positional_param_count {
                python_call_argument(call, index, &param)
            } else {
                call.keywords
                    .iter()
                    .find(|keyword| {
                        keyword.arg.as_ref().map(|name| name.as_str()) == Some(param.as_str())
                    })
                    .map(|keyword| &keyword.value)
            };
            if let Some(Expr::Name(receiver)) = argument {
                self.track_instance_attr_rebinding(receiver.id.as_str(), &attr);
                let propagated = (receiver.id.to_string(), attr);
                if caller_params.contains(&propagated.0)
                    && let Some(capture) = self.capture.as_mut()
                    && !capture.parameter_attr_writes.contains(&propagated)
                {
                    capture.parameter_attr_writes.push(propagated);
                }
            }
        }
    }

    /// Connect the arguments `call` binds to the effects, or the stdout, the
    /// summary just applied takes its parameters into. Inside a summary the
    /// arguments are read like any consumed argument; on the plan they are
    /// walked after the call, so the consumers wait for `flow_call`.
    fn bind_param_flows(&mut self, name: &str, call: &ast::ExprCall) {
        let arguments = call_arguments(call);
        let mut consumers = Vec::new();
        // The names the callee reads from an enclosing scope, which hold
        // their value when the call runs.
        let mut free = Vec::new();
        for (param, consumer) in std::mem::take(&mut self.applied_param_flows) {
            match self.bound_argument(name, call, &param) {
                PythonBoundArgument::Index(index) => consumers.push((index, consumer)),
                PythonBoundArgument::Free => free.push((param, consumer)),
                // A parameter the call leaves out holds what its default
                // did when the `def` ran.
                PythonBoundArgument::Default(default) => {
                    free.push((super::dataflow_capture::default_origin(&default), consumer));
                }
                PythonBoundArgument::Unknown | PythonBoundArgument::Missing => {}
            }
        }
        if self.capture.is_none() {
            for (origin, consumer) in free {
                if let Some(producer) = self.free_producer(&origin) {
                    self.wire_consumer(call, consumer, &[producer]);
                }
            }
            self.argument_consumers = (!consumers.is_empty()).then_some((call.range, consumers));
            return;
        }
        for (index, consumer) in consumers {
            self.capture_consumers(&[arguments[index]], vec![consumer]);
        }
        for (name, consumer) in free {
            self.capture_held_consumer(&name, consumer);
        }
    }

    pub(super) fn apply_local_root(&mut self, name: &str) {
        let span = self
            .defs
            .iter()
            .find(|def| def.name == name)
            .and_then(|def| def.body.first())
            .map(Ranged::range)
            .unwrap_or_default();
        self.apply_local_arguments(name, &[], span);
    }

    pub(super) fn apply_local_arguments(
        &mut self,
        name: &str,
        arguments: &[ValueArgument],
        span: TextRange,
    ) {
        self.ensure_summary(name);
        let Some(summary) = self.summaries.get(name) else {
            return;
        };
        let bindings = bind_arguments(&summary.params, arguments);
        self.apply_summary(name, &bindings, span);
    }

    pub(super) fn apply_context_method(
        &mut self,
        class: &str,
        method: &str,
        receiver: &SemanticValue,
        span: TextRange,
    ) -> Option<ResourceExpr> {
        let name = format!("{class}.{method}");
        self.ensure_summary(&name);
        let def = self.defs.iter().find(|def| def.name == name)?;
        let mut bindings = self.bind_with_defaults(
            &def.params,
            def.positional_param_count,
            &def.param_defaults,
            &[],
            true,
            true,
        );
        self.bind_receiver_attrs(class, receiver, None, &mut bindings);
        let returned = self
            .summaries
            .get(&name)
            .and_then(|summary| summary.returns.as_ref())
            .map(|returns| {
                substitute_value(returns, &bindings, self.nest.limits.value_limits())
                    .lower_resource()
            });
        self.apply_summary(&name, &bindings, span);
        returned
    }

    pub(super) fn apply_summary(
        &mut self,
        name: &str,
        bindings: &std::collections::HashMap<String, SemanticValue>,
        span: TextRange,
    ) {
        self.ensure_summary(name);
        self.invalidate_shared_vars();
        let Some((summary, spawns)) = self
            .summaries
            .get(name)
            .cloned()
            .map(|summary| {
                let spawns = self.spawn_summaries.get(name).cloned().unwrap_or_default();
                (summary, spawns)
            })
            .or_else(|| self.imported_summary(name))
        else {
            return;
        };
        if self.capture.is_none() {
            self.entered_callables = true;
        }
        let node = self.span_node(span);
        // Slots this call site's copies landed in, so the callee's recorded
        // transfer pairings survive substitution and nesting.
        let mut slots: Vec<Option<u32>> = Vec::with_capacity(summary.effects.len());
        for (index, effect) in summary.effects.iter().enumerate() {
            let mut specialized = effect.clone();
            if let Some(condition) = &mut specialized.condition {
                condition.rebind(
                    &self
                        .condition_source
                        .call_site(&(u32::from(span.start()), u32::from(span.end()))),
                );
            }
            specialized.condition = effinterp_proto::Condition::compose(
                specialized.condition.iter().chain(
                    self.builder
                        .condition_since(self.capture_condition_depth)
                        .iter(),
                ),
            );
            let mut visited = 0;
            let value = crate::substitute_value_counted(
                &SemanticValue::from(&effect.resource),
                bindings,
                self.nest.limits.value_limits(),
                &mut visited,
            );
            if !self.charge_steps(visited, (u32::from(span.start()), u32::from(span.end()))) {
                self.node_budget_hit = true;
                return;
            }
            // Keep network joins neutral while one function summary is folded
            // into another; the outer call site supplies the final URL anchor.
            if self.capture.is_some()
                && self.current_function.is_some()
                && specialized.operation.domain() == "network"
                && matches!(&value.kind, SemanticValueKind::Join(_))
            {
                specialized.resource = value.lower_resource();
            } else {
                crate::lower_effect_value(&mut specialized, &value);
            }
            specialized.provenance = vec![node];
            if self
                .capture
                .as_ref()
                .is_some_and(|cap| cap.effects.len() >= MAX_SUMMARY_EFFECTS)
            {
                self.summary_effect_dropped(&[specialized.operation.domain()], Some(node));
                slots.push(None);
                continue;
            }
            if self.capture.is_some()
                && !crate::nest::charge_analysis_bytes(
                    self.builder,
                    self.nest.budget,
                    crate::limits::retained_bytes(&specialized),
                    Some((span.start().into(), span.end().into())),
                )
            {
                return;
            }
            match self.capture.as_mut() {
                Some(cap) => {
                    cap.effects.push(specialized);
                    cap.effect_models.push(
                        summary
                            .effect_models
                            .get(index)
                            .cloned()
                            .unwrap_or_default(),
                    );
                    slots.push(Some(cap.effects.len() as u32 - 1));
                }
                None => {
                    // The call site is where the host environment applies, as
                    // for an effect emitted directly: `$HOME` passed into a
                    // function resolves exactly as `~` written at the call.
                    // A relative path passed in likewise names a file under
                    // the call site's cwd.
                    if specialized.operation.domain() == "filesystem" {
                        if let Some(cwd) = &self.cwd
                            && fs_resource_uses_cwd(&specialized.resource)
                        {
                            let cwd = std::collections::HashMap::from([(
                                "cwd".to_string(),
                                resolve_fs_path(cwd, None),
                            )]);
                            specialized.resource = normalize_resource(
                                substitute_resource_expr(&specialized.resource, &cwd),
                                PathPlatform::Posix,
                            );
                            specialized.provenance.extend(self.cwd_node);
                        }
                        specialized.resource = self.resolve_host_path(
                            specialized.resource.clone(),
                            &mut specialized.provenance,
                        );
                    }
                    if specialized.operation.as_str() == "environment.write" {
                        self.environment_rewritten = true;
                    }
                    for model in summary.effect_models.get(index).into_iter().flatten() {
                        let application = self.builder.node(
                            ProvenanceKind::ModelApplication {
                                model: model.clone(),
                            },
                            &[node],
                        );
                        specialized.provenance.push(application);
                    }
                    slots.push(self.builder.effect(specialized));
                }
            }
        }
        for binding in &summary.transfers {
            let (Some(Some(source)), Some(Some(destination))) = (
                slots.get(binding.source as usize),
                slots.get(binding.destination as usize),
            ) else {
                continue;
            };
            self.record_transfer(Some(*source), Some(*destination));
        }
        // What the callee prints reaches this program's stdout too.
        let printed = self
            .summary_stdout
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|slot| slots.get(*slot as usize).copied().flatten())
            .collect::<Vec<_>>();
        match self.capture.as_mut() {
            Some(capture) => {
                capture.stdout.extend(printed);
                capture.stdout.sort_unstable();
                capture.stdout.dedup();
            }
            None => {
                self.mark_printed_environment_reads(&printed);
                crate::flow::effects_to_stdout(
                    self.builder,
                    printed,
                    effinterp_proto::CausalAssurance::Conservative,
                    vec![node],
                )
            }
        }
        // A value the callee passes from one of its effects to another
        // flows between this call site's copies of them.
        let flows = self
            .summary_flows
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|(producer, consumer)| {
                Some((
                    slots.get(*producer as usize).copied().flatten()?,
                    slots.get(*consumer as usize).copied().flatten()?,
                ))
            })
            .collect::<Vec<_>>();
        self.applied_param_flows = self
            .summary_param_flows
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|(param, consumer)| {
                let consumer = match consumer {
                    Some(slot) => Some(slots.get(*slot as usize).copied().flatten()?),
                    None => None,
                };
                Some((param.clone(), consumer))
            })
            .collect();
        self.applied_writes = self
            .summary_writes
            .get(name)
            .into_iter()
            .flatten()
            .map(|write| super::SummaryWrite {
                effects: write
                    .effects
                    .iter()
                    .filter_map(|slot| slots.get(*slot as usize).copied().flatten())
                    .collect(),
                ..write.clone()
            })
            .collect();
        match self.capture.as_mut() {
            Some(capture) => capture.flows.extend(flows),
            None => {
                for (producer, consumer) in flows {
                    let producer = self.stage_writer.value_stage(node, vec![producer]);
                    let consumer = self.stage_writer.value_stage(node, vec![consumer]);
                    self.stage_writer.add_edge(producer, consumer, 0);
                }
            }
        }
        // What the callee returns is the value of this call, for the caller
        // that binds or prints it.
        let returned = self
            .summary_returns
            .get(name)
            .into_iter()
            .flatten()
            .map(|site| CallReturn {
                callee: name.to_string(),
                site: ReturnSite {
                    effects: site
                        .effects
                        .iter()
                        .filter_map(|slot| slots.get(*slot as usize).copied().flatten())
                        .collect(),
                    ..site.clone()
                },
            })
            .collect::<Vec<_>>();
        if !returned.is_empty() {
            let call_returns = match self.capture.as_mut() {
                Some(capture) => &mut capture.call_returns,
                None => &mut self.call_returns,
            };
            call_returns.entry(span).or_default().extend(returned);
        }
        // A summary still converging in a recursive group proves nothing yet.
        let application = match self.summary_requirements.get(name) {
            Some(requirements)
                if !self.summary_in_progress.contains(name)
                    && !self.summary_cycles.contains(name) =>
            {
                SiteFacts::call(requirements, |fact| match fact {
                    ControlFact::Effect(index) => slots
                        .get(index as usize)
                        .copied()
                        .flatten()
                        .map(ControlFact::Effect),
                    ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
                })
            }
            _ => SiteFacts::unknown(),
        };
        self.control_applications.push(application);
        let source_spans = self.summary_spans.get(name).cloned().unwrap_or_default();
        for boundary in &summary.boundaries {
            if self.capture.as_ref().is_some_and(|cap| {
                cap.boundaries.iter().any(|old| {
                    old.reason == boundary.reason
                        && old.limit == boundary.limit
                        && old.callee == boundary.callee
                        && old.detail == boundary.detail
                })
            }) {
                continue;
            }
            let mut b = boundary.clone();
            if b.reason == BoundaryReason::CROSS_MODULE
                && let Some(resource) = &b.affected_resource
            {
                let specialized = crate::substitute_value(
                    &SemanticValue::from(resource),
                    bindings,
                    self.nest.limits.value_limits(),
                )
                .lower_resource();
                if specialized != *resource
                    && let Some(path) = python_plugin_path_pattern(&specialized)
                {
                    b.detail = Some(format!(
                        "{}; recovered path {path}",
                        b.detail
                            .as_deref()
                            .unwrap_or_default()
                            .split("; recovered path ")
                            .next()
                            .unwrap_or_default()
                    ));
                }
                b.affected_resource = Some(specialized);
            }
            b.provenance = vec![node];
            for reference in &boundary.provenance {
                if let Some(span) = source_spans.get(reference.0 as usize) {
                    b.provenance.push(self.span_node(*span));
                }
            }
            self.out_boundary(b);
        }
        for (domain, level) in &summary.coverage {
            self.out_coverage(domain.clone(), *level);
        }
        for spawn in spawns {
            self.apply_deferred_spawn(spawn, bindings, node, span);
        }
    }
}
