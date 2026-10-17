//! Deferred processes: a body that runs beside the command reading or writing
//! its channel, such as a process substitution or a coprocess. The body is
//! walked once its consumer has been (`finish_deferred`), in the child
//! environment `defer_process` prepared.

use std::rc::Rc;

use effinterp_proto::{BoundaryClass, BoundaryReason, Port, ProvenanceKind, Subject};

use crate::builder::PlanBuilder;
use crate::flow::{Descriptor, Flow, FlowReason, FlowRef, FlowStage};
use crate::models::StdinValue;
use crate::nest::Transition;
use crate::shell::lex::ShellSpan;
use crate::shell::shell_env::{ArrayValue, DeferredProcess, ShellEnv};
use crate::shell::{Converted, Shell, analyze_shell_with_env};
use crate::word::{Word, WordPart};

use super::redirection::descriptor_word;

impl Shell<'_> {
    /// Record `source` as a deferred process and return the flow stage standing
    /// for its channel. The body starts from a child environment taken here, with
    /// its stdout captured into the channel; `None` when the analysis budget is
    /// spent or the walk is structurally saturated.
    pub(in crate::shell) fn defer_process(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: ShellSpan,
    ) -> Option<u32> {
        if !self.charge(builder, 1, source.len() as u64, span)
            || self.structural_saturated(builder, env)
        {
            return None;
        }
        let node = self.span_node(builder, span);
        let stage = builder.pending_flow_stage(FlowStage {
            execution: None,
            effects: Vec::new(),
            bindings: Vec::new(),
            provenance: vec![node],
        }) as u32;
        builder.keep_pending_flow_stage(stage);
        let mut child = self.child_env(env);
        child.capture_stdout();
        child.socket_fds.remove(&Descriptor::Number(0));
        child.redirections.push(crate::flow::Redirection {
            role: crate::flow::RedirRole::Inherited(Descriptor::Number(0)),
            fd: Descriptor::Number(0),
            dup: None,
            both: false,
            read_effect: None,
            write_effect: None,
        });
        child.stdout_channel = Some(stage);
        // What the body's builtins print into the channel is collected for
        // `finish_deferred`, which binds it to the channel's output.
        child.captured_values = Some(Rc::default());
        env.channel_bytes
            .borrow_mut()
            .insert(stage, Some(String::new()));
        env.deferred.push(DeferredProcess {
            source: source.into(),
            span,
            stage,
            child: Box::new(child),
            condition: builder.current_condition(),
        });
        Some(stage)
    }

    /// `coproc [NAME] command`: a deferred process run as an asynchronous job,
    /// whose read and write descriptors are bound to the array `name`. A dynamic
    /// array name states an unresolved-source boundary.
    pub(in crate::shell) fn coprocess(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: Option<&str>,
        span: ShellSpan,
        conditional: bool,
    ) {
        let source = &self.source[span.start as usize..span.end as usize];
        let Some(stage) = self.defer_process(builder, env, source, span) else {
            return;
        };
        let child = &mut env.deferred.last_mut().unwrap().child;
        child.close_coprocess_descriptors();
        // A coprocess is an asynchronous job, so recursion through it grows
        // processes like a `&` job does.
        child.background_depth += 1;
        let Some(name) = name else {
            for array in env.arrays.values_mut() {
                *array = ArrayValue::Unknown(Vec::new());
            }
            env.channel_bytes.borrow_mut().insert(stage, None);
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "coprocess descriptor array name is dynamic",
                span,
            );
            return;
        };
        let mut elements = Vec::new();
        for end in ["read", "write"] {
            let span_node = self.span_node(builder, span);
            let node = builder.node(
                ProvenanceKind::ModelApplication {
                    model: format!("shell/coproc/{end}@v0"),
                },
                &[span_node],
            );
            let descriptor = Descriptor::Allocated(node);
            env.coprocess_fds.push(descriptor);
            env.descriptor_values
                .push((descriptor_word(descriptor), descriptor));
            env.redirections.push(crate::flow::Redirection {
                role: crate::flow::RedirRole::Channel {
                    stage,
                    read: end == "read",
                    write: end == "write",
                },
                fd: descriptor,
                dup: None,
                both: false,
                read_effect: None,
                write_effect: None,
            });
            elements.push(Converted {
                word: descriptor_word(descriptor),
                raw: String::new(),
                span,
                assign_nodes: vec![node],
                producers: Vec::new(),
                alts: Vec::new(),
                pending_assigns: Vec::new(),
                unresolved_default_override: false,
                unquoted_substitution: false,
                captured_name_hidden: false,
                quoted_substitution: false,
            });
        }
        if conditional {
            env.arrays
                .insert(name.into(), ArrayValue::Unknown(Vec::new()));
            self.opaque_boundary(
                builder,
                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                BoundaryClass::Unresolved,
                "conditional coprocess descriptors are unresolved",
                span,
            );
        } else {
            env.arrays
                .insert(name.into(), ArrayValue::Definite(elements));
        }
    }

    /// Walk every deferred process recorded so far as a launched nested shell,
    /// under the condition it was deferred in, reading the bytes its channel was
    /// given on standard input.
    pub(in crate::shell) fn finish_deferred(&self, builder: &mut PlanBuilder, env: &mut ShellEnv) {
        for mut process in std::mem::take(&mut env.deferred) {
            let node = self.span_node(builder, process.span);
            if let Some(condition) = &process.condition {
                builder.push_condition(condition.clone());
            }
            let transition = Transition::file(Subject::Shell {
                source: process.source.clone(),
                cwd: process.child.cwd.clone(),
                context: Default::default(),
            })
            .kind(effinterp_proto::ExecutionEdgeKind::Launch)
            .cwd(process.child.cwd_resource.clone(), process.child.cwd_node)
            .streams(effinterp_proto::ExecutionStreams::default());
            if let Some(frame) = self.nest.begin(builder, transition, &[node], self.depth) {
                let content = env
                    .channel_bytes
                    .borrow()
                    .get(&process.stage)
                    .cloned()
                    .flatten();
                process.child.stdin = Some(StdinValue {
                    paths: None,
                    piped: true,
                    file: None,
                    word: content
                        .map(Word::literal)
                        .unwrap_or_else(|| Word::new(vec![WordPart::Unknown])),
                    provenance: vec![node],
                });
                analyze_shell_with_env(
                    builder,
                    self.nest,
                    &process.source,
                    &mut process.child,
                    Some(frame.scope),
                    self.depth + 1,
                );
                // The operand values `echo` and `printf` wrote, and what a
                // program copied from a here-string: bytes of the channel no
                // process of the body states. Whoever holds the descriptor
                // may print them, so a credential among them is taken to be.
                if let Some(values) = process.child.captured_values.take() {
                    let values = values.take();
                    crate::shell::disclosed_environment_reads::mark_printed_environment_reads(
                        builder, &values,
                    );
                    for from in values {
                        builder.pending_flow_edge(Flow {
                            assurance: effinterp_proto::CausalAssurance::Conservative,
                            from,
                            to: FlowRef {
                                stage: process.stage,
                                port: Port::Stdout,
                            },
                            reason: FlowReason::new("descriptor child"),
                            provenance: vec![node],
                        });
                    }
                }
                let selection = env
                    .channel_selections
                    .borrow()
                    .get(&process.stage)
                    .copied()
                    .flatten();
                builder.settle_channel_arguments(process.stage, selection);
                let child = builder.pending_flow_stage(FlowStage {
                    execution: Some(frame.execution),
                    effects: Vec::new(),
                    bindings: Vec::new(),
                    provenance: vec![node],
                }) as u32;
                for port in [Port::Stdin, Port::Stdout] {
                    let channel = FlowRef {
                        stage: process.stage,
                        port: port.clone(),
                    };
                    let child = FlowRef {
                        stage: child,
                        port: port.clone(),
                    };
                    let (from, to) = if port == Port::Stdin {
                        (channel, child)
                    } else {
                        (child, channel)
                    };
                    builder.pending_flow_edge(Flow {
                        assurance: effinterp_proto::CausalAssurance::Exact,
                        from,
                        to,
                        reason: FlowReason::new("descriptor child"),
                        provenance: vec![node],
                    });
                }
                frame.end(builder);
            }
            if process.condition.is_some() {
                builder.pop_condition();
            }
        }
    }
}
