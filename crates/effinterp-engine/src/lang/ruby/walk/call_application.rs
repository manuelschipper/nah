use std::collections::HashMap;
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ResourceExpr,
};
use lib_ruby_parser::nodes::Send;

use crate::ObjectIdentity;
use crate::control_flow::{ControlFact, SiteFacts};
use crate::module_summary::CallEdge;
use crate::summary::substitute_resource_expr;

use super::super::call_resolution::{resolve_same_file_ruby_call, unmodeled_ruby_receiver_call};
use super::super::model::{network_sink, resolve};
use super::super::resource_bindings::{
    bind_ruby_call_resources, instance_bindings, unresolved_instance_parameters,
};
use super::super::spawn_resources::substitute_ruby_spawn;
use super::super::summary_capture::capture_ruby_summary;
use super::super::{DOMAINS, MAX_CALL_SITE_APPLICATIONS};
use super::RubyWalker;

impl RubyWalker<'_> {
    /// Apply a registered command root with symbolic parameters and deduplicate repeated applications.
    pub(super) fn apply_ruby_command_root(&mut self, key: &str) {
        let Some(definition) = self.ctx.method_definition(key) else {
            return;
        };
        let params = definition.params.clone();
        let body = definition.body.clone();
        let class = definition.class.clone();
        let Some(body) = body else { return };
        let bindings: HashMap<String, ResourceExpr> = params
            .iter()
            .map(|name| (name.clone(), ResourceExpr::Parameter { name: name.clone() }))
            .collect();
        let application = rendered_bindings(&bindings);
        if !self
            .applications
            .entry(key.to_string())
            .or_default()
            .insert(application)
        {
            return;
        }
        let inner = self
            .captures
            .entry(key.to_string())
            .or_insert_with(|| {
                Rc::new(capture_ruby_summary(
                    Some(&body),
                    &params,
                    class.as_deref(),
                    self.ctx,
                ))
            })
            .clone();
        let expression = body.expression();
        let mut slots = Vec::with_capacity(inner.effects.len());
        for mut effect in inner.effects.iter().cloned() {
            effect.resource = substitute_resource_expr(&effect.resource, &bindings);
            unresolved_instance_parameters(&mut effect.resource);
            if effect.operation.domain() == "network" {
                effect.resource = network_sink(effect.resource);
            }
            slots.push(self.emit(effect, expression.begin, expression.end));
        }
        crate::summary::replay_transfers(self.builder, &inner.transfers, &slots);
        for (spawn, condition) in inner.spawns.iter().cloned() {
            self.spawn_guarded(
                substitute_ruby_spawn(spawn, &bindings),
                condition,
                expression.begin,
                expression.end,
            );
        }
        for boundary in inner.boundaries.iter().cloned() {
            self.builder.boundary(boundary);
        }
    }

    /// Apply a same-file callee's summary at a send; its guarantees when
    /// its occurrences were emitted here.
    pub(super) fn apply_same_file_ruby_call(
        &mut self,
        edge: &CallEdge,
        s: &Send,
    ) -> Option<SiteFacts> {
        let Some(key) = resolve_same_file_ruby_call(self.ctx, edge) else {
            // A bare call or a constant's singleton method may name a global
            // definition from a required file.
            if edge.receiver.as_ref().is_none_or(|receiver| {
                matches!(
                    receiver.as_object().map(|object| &object.identity),
                    Some(ObjectIdentity::ModuleBinding { .. })
                )
            }) {
                let site = self.span(s.expression_l.begin, s.expression_l.end);
                if crate::dependency_calls::apply_global_dependency_call(
                    self.builder,
                    self.nest,
                    "ruby",
                    &edge.callee,
                    &edge.arguments,
                    site,
                ) {
                    return None;
                }
            }
            if edge.receiver.is_none() && !edge.callee.contains('.') {
                self.unresolved_call(&edge.callee, s);
            } else {
                let callee = unmodeled_ruby_receiver_call(s, self.ctx)
                    .unwrap_or_else(|| edge.callee.clone());
                self.unresolved_call(&callee, s);
            }
            return None;
        };
        let (params, defaults, keywords, body, class) = {
            let d = self.ctx.method_definition(&key).expect("local_key checked");
            (
                d.params.clone(),
                d.defaults.clone(),
                d.keywords.clone(),
                d.body.clone(),
                d.class.clone(),
            )
        };
        let mut bindings = bind_ruby_call_resources(&params, &keywords, &edge.arguments);
        let mut default_effects = Vec::new();
        for (name, default) in defaults {
            if let std::collections::hash_map::Entry::Vacant(e) = bindings.entry(name) {
                e.insert(resolve(&default, &self.env, self.cwd));
                default_effects.push(default);
            }
        }
        bindings.extend(instance_bindings(
            s,
            &self.instances,
            &self.env,
            self.cwd,
            None,
            self.ctx,
        ));
        let inner = self
            .captures
            .entry(key.clone())
            .or_insert_with(|| {
                Rc::new(capture_ruby_summary(
                    body.as_deref(),
                    &params,
                    class.as_deref(),
                    self.ctx,
                ))
            })
            .clone();
        let mut application = rendered_bindings(&bindings);
        if inner
            .effects
            .iter()
            .any(|effect| effect.condition.is_some())
            || inner
                .spawns
                .iter()
                .any(|(_, condition)| condition.is_some())
            || self.builder.current_condition().is_some()
        {
            application.push_str(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(
                    s.expression_l.begin,
                    s.expression_l.end,
                    self.builder
                        .current_condition()
                        .as_ref()
                        .map(effinterp_proto::Condition::identity),
                ),
            ));
        }
        let applications = self.applications.entry(key.clone()).or_default();
        if applications.contains(&application) {
            return None;
        }
        if applications.len() >= MAX_CALL_SITE_APPLICATIONS {
            if !self.call_site_limit_reported {
                self.call_site_limit_reported = true;
                self.builder.boundary(Boundary {
                    reason: BoundaryReason::PARTIAL_ANALYSIS,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
                    provenance: self.scope.as_slice().to_vec(),
                    limit: Some("max_ruby_call_sites".to_string()),
                    detail: Some("ruby call-site application limit exceeded".to_string()),
                });
            }
            return None;
        }
        applications.insert(application);
        for default in default_effects {
            self.stmt(&default);
        }
        let mut slots = Vec::with_capacity(inner.effects.len());
        for mut e in inner.effects.iter().cloned() {
            e.resource = substitute_resource_expr(&e.resource, &bindings);
            unresolved_instance_parameters(&mut e.resource);
            if e.operation.domain() == "network" {
                e.resource = network_sink(e.resource);
            }
            slots.push(self.emit(e, s.expression_l.begin, s.expression_l.end));
        }
        crate::summary::replay_transfers(self.builder, &inner.transfers, &slots);
        for b in inner.boundaries.iter().cloned() {
            self.builder.boundary(b);
        }
        for (spawn, condition) in inner.spawns.iter().cloned() {
            self.spawn_guarded(
                substitute_ruby_spawn(spawn, &bindings),
                condition,
                s.expression_l.begin,
                s.expression_l.end,
            );
        }
        // Follow the callee's own local edges one level down (chained local
        // calls are already inlined into its captured effects).
        inner.control.as_ref().map(|requirements| {
            SiteFacts::call(requirements, |fact| match fact {
                ControlFact::Effect(index) => slots
                    .get(index as usize)
                    .copied()
                    .flatten()
                    .map(ControlFact::Effect),
                ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
            })
        })
    }
}

fn rendered_bindings(bindings: &HashMap<String, ResourceExpr>) -> String {
    let mut entries: Vec<_> = bindings.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    format!("{entries:?}")
}
