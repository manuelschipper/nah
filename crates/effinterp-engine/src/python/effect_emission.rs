//! Python effect emission: how the walker emits effects, requests, transfers,
//! boundaries and coverage to the plan or the active summary, and how it nests
//! or defers the shell commands and Python sources a program spawns.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionEdgeKind, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr,
    Subject,
};
use rustpython_parser::ast::Ranged;
use rustpython_parser::text_size::TextRange;

use crate::SemanticValue;
use crate::builder::RuntimeShell;
use crate::nest::{Transition, word_resource};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;
use crate::word::Word;

use super::{
    DOMAINS, DeferredArgv, DeferredSpawn, MAX_SUMMARY_BOUNDARIES, MAX_SUMMARY_EFFECTS,
    PythonWalker, argv_to_words, resource_command_string, resource_path_string, shell_program,
    substitute_deferred_spawn,
};

impl PythonWalker<'_, '_> {
    pub(super) fn emit(
        &mut self,
        operation: &str,
        resource: ResourceExpr,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) -> Option<u32> {
        let attributes = attrs
            .iter()
            .filter(|(_, on)| *on)
            .map(|(k, _)| (k.to_string(), AttrValue::Bool(true)))
            .collect();
        self.emit_request(operation, resource, attributes, node, None)
    }

    /// `emit` for an API whose `model` certifies the request exactly. The
    /// attributes are fixed here because a later rewrite discards that proof.
    pub(super) fn emit_request(
        &mut self,
        operation: &str,
        resource: ResourceExpr,
        attributes: std::collections::BTreeMap<String, AttrValue>,
        node: ProvenanceRef,
        model: Option<&str>,
    ) -> Option<u32> {
        let mut provenance = vec![node];
        if let Some(model) = model
            && self.capture.is_none()
        {
            provenance.push(self.builder.node(
                ProvenanceKind::ModelApplication {
                    model: model.to_string(),
                },
                &[node],
            ));
        }
        let mut resource = resource;
        if operation.starts_with("filesystem.") {
            if fs_resource_uses_cwd(&resource) {
                provenance.extend(self.cwd_node);
            }
            resource = self.resolve_host_path(resource, &mut provenance);
        }
        if operation == "environment.write" {
            self.environment_rewritten = true;
        }
        let effect = Effect {
            request_assurance: match model {
                Some(_) => effinterp_proto::RequestAssurance::Exact,
                None => effinterp_proto::RequestAssurance::Conservative,
            },
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: self.builder.condition_since(self.capture_condition_depth),
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        };
        if self
            .capture
            .as_ref()
            .is_some_and(|cap| cap.effects.len() >= MAX_SUMMARY_EFFECTS)
        {
            self.summary_effect_dropped(&[effect.operation.domain()], Some(node));
            return None;
        }
        if self.capture.is_some()
            && !crate::nest::charge_analysis_bytes(
                self.builder,
                self.nest.budget,
                crate::limits::retained_bytes(&effect),
                self.callable_span(),
            )
        {
            return None;
        }
        match self.capture.as_mut() {
            Some(cap) => {
                cap.effects.push(effect);
                cap.effect_models
                    .push(model.into_iter().map(str::to_string).collect());
                Some(cap.effects.len() as u32 - 1)
            }
            None => self.builder.effect(effect),
        }
    }

    /// Record that the active summary is full and something affecting
    /// `domains` was left out of it. Every call site then reads partial on
    /// those domains instead of taking the truncated summary for the whole
    /// function.
    pub(super) fn summary_effect_dropped(&mut self, domains: &[&str], node: Option<ProvenanceRef>) {
        const LIMIT: &str = "max_summary_effects";
        let domains: Vec<Domain> = domains.iter().map(|domain| Domain::new(*domain)).collect();
        for domain in &domains {
            self.out_coverage(domain.clone(), CoverageLevel::Partial);
        }
        // One boundary per domain is enough; a long function would otherwise
        // spend the whole boundary buffer repeating it.
        if self.capture.as_ref().is_some_and(|cap| {
            domains.iter().all(|domain| {
                cap.boundaries.iter().any(|boundary| {
                    boundary.limit.as_deref() == Some(LIMIT) && boundary.domains.contains(domain)
                })
            })
        }) {
            return;
        }
        self.out_boundary(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains,
            provenance: node.into_iter().collect(),
            limit: Some(LIMIT.into()),
            detail: self.current_function.clone(),
        });
    }

    /// Record that `source` is the source side of one modeled transfer whose
    /// destination side is `destination`, in whichever effect list received
    /// them.
    pub(super) fn record_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        let (Some(source), Some(destination)) = (source, destination) else {
            return;
        };
        let binding = TransferBinding::new(source, destination);
        match self.capture.as_mut() {
            Some(cap) => {
                if !cap.transfers.contains(&binding) {
                    cap.transfers.push(binding);
                }
            }
            None => self.builder.transfer_binding(binding),
        }
    }

    pub(super) fn callable_span(&self) -> Option<(u32, u32)> {
        let name = self.current_function.as_ref()?;
        let span = self
            .defs
            .iter()
            .find(|def| &def.name == name)?
            .body
            .first()?
            .range();
        Some((span.start().into(), span.end().into()))
    }

    /// Emit a boundary to the plan, or collect it into the active summary.
    pub(super) fn out_boundary(&mut self, boundary: Boundary) {
        let span = self.callable_span();
        match self.capture.as_mut() {
            Some(cap) => {
                if cap.boundaries.len() >= MAX_SUMMARY_BOUNDARIES {
                    if boundary.class != BoundaryClass::Limit {
                        return;
                    }
                    // Keep the callable's refusal when its opaque-call buffer is full.
                    cap.boundaries.pop();
                }
                if crate::nest::charge_analysis_bytes(
                    self.builder,
                    self.nest.budget,
                    crate::limits::boundary_retained_bytes(&boundary),
                    span,
                ) {
                    cap.boundaries.push(boundary);
                }
            }
            None => {
                self.builder.boundary(boundary);
            }
        }
    }

    /// Declare coverage on the plan, or record it on the active summary.
    pub(super) fn out_coverage(&mut self, domain: Domain, level: CoverageLevel) {
        match self.capture.as_mut() {
            Some(cap) => {
                if !cap.coverage.contains(&(domain.clone(), level)) {
                    cap.coverage.push((domain, level));
                }
            }
            None => self.builder.declare_coverage(domain, level),
        }
    }

    pub(super) fn emit_process_unresolved(&mut self, node: ProvenanceRef) {
        self.emit("process.exec", unresolved_resource("process"), &[], node);
    }

    pub(super) fn nest(
        &mut self,
        subject: Subject,
        node: ProvenanceRef,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
    ) {
        if self.capture.is_some() {
            let spawn = match &subject {
                Subject::Exec { argv, .. } => DeferredSpawn::Exec {
                    argv: DeferredArgv::Words(
                        argv.iter()
                            .map(|value| match value.as_str() {
                                "?" => unresolved_resource("process"),
                                _ => ResourceExpr::Literal {
                                    value: value.clone(),
                                },
                            })
                            .collect(),
                    ),
                    cwd: cwd_resource.clone(),
                    cwd_uses_ambient: cwd_node.is_some(),
                },
                Subject::Shell { source, .. } => DeferredSpawn::Shell {
                    source: ResourceExpr::Literal {
                        value: source.clone(),
                    },
                    cwd: cwd_resource.clone(),
                    cwd_uses_ambient: cwd_node.is_some(),
                    shell: None,
                    dynamic_detail: "subprocess with non-literal command".to_string(),
                },
                _ => DeferredSpawn::Exec {
                    argv: DeferredArgv::Words(Vec::new()),
                    cwd: cwd_resource.clone(),
                    cwd_uses_ambient: cwd_node.is_some(),
                },
            };
            self.push_deferred_spawn(spawn);
            return;
        }
        let source_cwd = self.nest.current_source_cwd();
        {
            let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
            self.nest.nest(
                self.builder,
                Transition::file(subject)
                    .source_cwd(source_cwd.as_deref())
                    .runtime_cwd(runtime_cwd.as_deref())
                    .cwd(cwd_resource, cwd_node),
                &[node],
                self.depth,
            );
        };
    }

    pub(super) fn opaque_boundary(&mut self, detail: &str, node: ProvenanceRef) {
        for domain in DOMAINS {
            self.out_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }

    pub(super) fn push_deferred_spawn(&mut self, spawn: DeferredSpawn) {
        let span = self.callable_span();
        // A spawn left out of a full summary could have done anything.
        if self.capture.as_ref().is_some_and(|cap| {
            cap.deferred_spawns.len() >= MAX_SUMMARY_EFFECTS
                && !cap.deferred_spawns.contains(&spawn)
        }) {
            self.summary_effect_dropped(&DOMAINS, None);
            return;
        }
        if let Some(cap) = self.capture.as_mut()
            && !cap.deferred_spawns.contains(&spawn)
        {
            let bytes = crate::limits::NODE_BYTES
                + match &spawn {
                    DeferredSpawn::Exec { argv, cwd, .. } => {
                        let argv_bytes = match argv {
                            DeferredArgv::Words(words) => {
                                crate::limits::NODE_BYTES
                                    + words.iter().map(crate::limits::resource_bytes).sum::<u64>()
                            }
                            DeferredArgv::Sequence(value) => crate::limits::resource_bytes(value),
                        };
                        argv_bytes + cwd.as_ref().map_or(0, crate::limits::resource_bytes)
                    }
                    DeferredSpawn::Shell {
                        source,
                        cwd,
                        shell,
                        dynamic_detail,
                        ..
                    } => {
                        crate::limits::resource_bytes(source)
                            + cwd.as_ref().map_or(0, crate::limits::resource_bytes)
                            + shell.as_ref().map_or(0, crate::limits::resource_bytes)
                            + dynamic_detail.len() as u64
                    }
                    DeferredSpawn::Command { argv } => {
                        argv.iter().map(|word| word.len() as u64).sum::<u64>()
                    }
                };
            if crate::nest::charge_analysis_bytes(self.builder, self.nest.budget, bytes, span) {
                cap.deferred_spawns.push(spawn);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn defer_or_nest_exec(
        &mut self,
        argv: DeferredArgv,
        cwd: Option<String>,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
        node: ProvenanceRef,
        symbolic_arg: bool,
        symbolic_detail: &str,
    ) {
        if self.capture.is_some() {
            self.push_deferred_spawn(DeferredSpawn::Exec {
                argv,
                cwd: cwd_resource,
                cwd_uses_ambient: cwd_node.is_some(),
            });
            return;
        }
        let words = argv_to_words(
            &argv,
            &std::collections::HashMap::new(),
            self.nest.limits.value_limits(),
        );
        if words.is_empty() {
            self.emit_process_unresolved(node);
            return;
        }
        self.nest.nest(
            self.builder,
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(cwd.as_deref())
                .cwd(cwd_resource, cwd_node)
                .runtime_cwd(cwd.as_deref())
                .kind(ExecutionEdgeKind::Launch),
            &[node],
            self.depth,
        );
        if symbolic_arg {
            self.opaque_boundary(symbolic_detail, node);
        }
    }

    /// Enter source this program evaluates at runtime as a nested program of
    /// the same language.
    pub(super) fn nest_python_source(&mut self, source: &str, span: TextRange) {
        let node = self.span_node(span);
        self.nest(
            Subject::Source {
                language: "python".to_string(),
                dialect: None,
                source: source.to_string(),
                cwd: self.cwd.clone(),
                context: Default::default(),
            },
            node,
            None,
            self.cwd_node,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn defer_or_nest_shell(
        &mut self,
        source: ResourceExpr,
        cwd: Option<String>,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
        node: ProvenanceRef,
        shell: Option<ResourceExpr>,
        dynamic_detail: &str,
    ) {
        if self.capture.is_some() {
            self.push_deferred_spawn(DeferredSpawn::Shell {
                source,
                cwd: cwd_resource,
                cwd_uses_ambient: cwd_node.is_some(),
                shell,
                dynamic_detail: dynamic_detail.to_string(),
            });
            return;
        }
        match resource_command_string(&source) {
            Some(cmd) => {
                let subject = Subject::Shell {
                    source: cmd,
                    cwd,
                    context: Default::default(),
                };
                let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
                self.nest.nest(
                    self.builder,
                    Transition::file(subject)
                        .source_cwd(self.nest.current_source_cwd().as_deref())
                        .runtime_cwd(runtime_cwd.as_deref())
                        .cwd(cwd_resource, cwd_node)
                        .runtime_shell(shell.as_ref().map(|shell| {
                            resource_command_string(shell)
                                .map_or(RuntimeShell::Unresolved, RuntimeShell::Program)
                        })),
                    &[node],
                    self.depth,
                );
            }
            // The shell runs a command this frontend cannot recover as its
            // `-c` script; the shell model reports that script as unrecoverable.
            None => self.defer_or_nest_exec(
                DeferredArgv::Words(vec![
                    shell_program(shell.as_ref()),
                    ResourceExpr::Literal {
                        value: "-c".to_string(),
                    },
                    unresolved_resource("process"),
                ]),
                cwd,
                cwd_resource,
                cwd_node,
                node,
                false,
                dynamic_detail,
            ),
        }
    }

    pub(super) fn apply_deferred_spawn(
        &mut self,
        spawn: DeferredSpawn,
        bindings: &std::collections::HashMap<String, SemanticValue>,
        node: ProvenanceRef,
        span: TextRange,
    ) {
        let spawn = substitute_deferred_spawn(spawn, bindings, self.nest.limits.value_limits());
        if self.capture.is_some() {
            self.push_deferred_spawn(spawn);
            return;
        }
        match spawn {
            DeferredSpawn::Exec {
                argv,
                cwd,
                cwd_uses_ambient,
            } => {
                let words = argv_to_words(&argv, bindings, self.nest.limits.value_limits());
                if words.is_empty() {
                    self.emit_process_unresolved(node);
                    return;
                }
                let cwd_resource = cwd.clone();
                let cwd_path = cwd_resource.as_ref().and_then(resource_path_string);
                let cwd_node = if cwd_uses_ambient {
                    self.cwd_node
                } else {
                    cwd_resource
                        .as_ref()
                        .is_some_and(fs_resource_uses_cwd)
                        .then_some(self.cwd_node)
                        .flatten()
                };
                if !self.charge_steps(1, (u32::from(span.start()), u32::from(span.end()))) {
                    self.node_budget_hit = true;
                    return;
                }
                self.nest.nest(
                    self.builder,
                    Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                        .exec_cwd(cwd_path.as_deref())
                        .cwd(cwd_resource, cwd_node)
                        .runtime_cwd(cwd_path.as_deref())
                        .kind(ExecutionEdgeKind::Launch),
                    &[node],
                    self.depth,
                );
            }
            DeferredSpawn::Shell {
                source,
                cwd,
                cwd_uses_ambient,
                shell,
                dynamic_detail,
            } => {
                let cwd_resource = cwd.clone();
                let cwd_path = cwd_resource.as_ref().and_then(resource_path_string);
                let cwd_node = cwd_uses_ambient.then_some(self.cwd_node).flatten();
                self.defer_or_nest_shell(
                    source,
                    cwd_path,
                    cwd_resource,
                    cwd_node,
                    node,
                    shell,
                    &dynamic_detail,
                );
            }
            DeferredSpawn::Command { argv } => {
                if !self.charge_steps(1, (u32::from(span.start()), u32::from(span.end()))) {
                    self.node_budget_hit = true;
                    return;
                }
                let argv = argv.into_iter().map(Word::literal).collect::<Vec<_>>();
                let runtime_cwd = self.nest.current_runtime_cwd();
                crate::models::apply_in_process_command(
                    self.builder,
                    self.nest,
                    &argv,
                    self.cwd.as_deref(),
                    runtime_cwd.as_deref(),
                    node,
                    self.depth,
                );
            }
        }
    }
}
