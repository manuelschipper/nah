use std::collections::HashMap;

use effinterp_proto::{Effect, ProvenanceKind, ProvenanceRef, ResourceExpr};

use crate::SemanticValue;
use crate::paths::fs_resource_uses_cwd;
use crate::summary::substitute_resource_expr;
use crate::value::fs_path_resource;

use super::RubyWalker;

impl RubyWalker<'_> {
    /// Emit one effect and report its plan slot, so a transfer emitter can
    /// pair the endpoints it just produced.
    pub(super) fn emit(&mut self, effect: Effect, begin: usize, end: usize) -> Option<u32> {
        self.emit_applying(effect, begin, end, None)
    }

    /// `emit`, attributing the effect to the named model's application.
    pub(super) fn emit_applying(
        &mut self,
        mut effect: Effect,
        begin: usize,
        end: usize,
        model: Option<&str>,
    ) -> Option<u32> {
        if let Some(condition) = &mut effect.condition {
            condition.rebind(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(&self.ctx.source_digest, begin, end),
            ));
        }
        let guard = self.ctx.guards.at(effinterp_proto::ByteSpan {
            start: begin as u32,
            end: end as u32,
        });
        effect.condition =
            effinterp_proto::Condition::compose(effect.condition.iter().chain(guard.iter()));
        let mut environment_nodes = Vec::new();
        if effect.operation.as_str() == "environment.write" {
            self.environment_rewritten = true;
        } else if effect.operation.domain() == "filesystem" {
            effect.resource = self.resolve_host_path(effect.resource, &mut environment_nodes);
        }
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        let node = self.span(begin, end);
        // A blob is marked only in code the request supplies.
        if !self.builder.source_from_subject(Some(node)) {
            effect.attributes.remove(crate::embedded_archive::ATTRIBUTE);
        }
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
        if effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource) {
            effect.provenance.extend(self.cwd_node);
            // A relative path names a file under the process's working
            // directory; bind it when the invocation states that directory,
            // as `File.expand_path` already does.
            if let Some(cwd) = self.cwd {
                effect.resource = substitute_resource_expr(
                    &effect.resource,
                    &HashMap::from([("cwd".to_string(), fs_path_resource(cwd))]),
                );
            }
        }
        self.builder.effect(effect)
    }

    /// A filesystem path with `ENV[...]` references replaced by the values the
    /// enclosing execution or host supplied, so `File.join(ENV["HOME"], x)`
    /// names the same file as the path written out.
    fn resolve_host_path(
        &mut self,
        mut resource: ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) -> ResourceExpr {
        let before = provenance.len();
        self.resolve_host_environment(&mut resource, provenance);
        if provenance.len() == before {
            return resource;
        }
        match effinterp_proto::normalize_resource(resource, effinterp_proto::PathPlatform::Posix) {
            ResourceExpr::Literal { value } => fs_path_resource(&value),
            resource => resource,
        }
    }

    fn resolve_host_environment(
        &mut self,
        resource: &mut ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) {
        match resource {
            ResourceExpr::Environment { name } => {
                let Some(value) = self.host_environment_value(name) else {
                    return;
                };
                let node = self.nest.current_environment_node(name).unwrap_or_else(|| {
                    self.builder.node(
                        ProvenanceKind::HostContext {
                            name: format!("env.{name}"),
                        },
                        &[],
                    )
                });
                provenance.push(node);
                *resource = value;
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                for part in parts {
                    self.resolve_host_environment(part, provenance);
                }
            }
            _ => {}
        }
    }

    /// The effective value of one environment name, preferring an override the
    /// enclosing execution established over the value the host supplied.
    fn host_environment_value(&self, name: &str) -> Option<ResourceExpr> {
        if self.environment_rewritten || self.nest.current_environment_unsets().contains(name) {
            return None;
        }
        if let Some(value) = self
            .nest
            .environments
            .borrow()
            .last()
            .and_then(|environment| environment.get(name))
        {
            return value.clone();
        }
        self.nest
            .context
            .and_then(|context| context.env.get(name))
            .map(|value| ResourceExpr::Literal {
                value: value.clone(),
            })
    }

    /// Attach an effect's source span to the current execution scope.
    pub(super) fn span(&mut self, begin: usize, end: usize) -> ProvenanceRef {
        self.builder.node(
            ProvenanceKind::SourceSpan {
                start: begin as u32,
                end: end as u32,
            },
            self.scope.as_slice(),
        )
    }
}
