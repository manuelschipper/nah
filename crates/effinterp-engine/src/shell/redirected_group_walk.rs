//! Redirected group walk: a compound command with trailing redirections
//! (`{ ...; } > file`, `while ...; done < file`), and the pipeline consumer it
//! feeds when it starts one.

use effinterp_proto::Port;

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, Descriptor, FlowStage, PortBinding};
use crate::models::StdinValue;
use crate::word::Word;

use super::lex::RedirKind;
use super::parse::ShellItem;
use super::shell_env::ShellEnv;
use super::{Shell, Termination, parse};

impl Shell<'_> {
    /// A compound command with trailing redirections, and the pipeline
    /// consumer it feeds when it starts one. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame size bounds nesting.
    #[inline(never)]
    pub(super) fn walk_redirected(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) -> Option<(Termination, u32)> {
        let [redirect, body, consumer @ ..] = items else {
            unreachable!("a redirected group holds its redirections and body")
        };
        // Each pipeline stage is its own subshell of the pipeline's entry
        // state: the body's variables, functions and cwd never reach the
        // consumer. With `lastpipe` the consumer runs in the current shell.
        // Boxed: this frame recurses with the walk.
        let mut producer = (!consumer.is_empty()).then(|| {
            let mut child = Box::new(self.child_env(env));
            child.close_coprocess_descriptors();
            child
        });
        let consumer_entry =
            (!consumer.is_empty() && !env.lastpipe).then(|| Box::new(self.child_env(env)));
        let caller = &mut *env;
        let env: &mut ShellEnv = match producer.as_deref_mut() {
            Some(producer) => producer,
            None => &mut *caller,
        };
        let outer_stdin = env.stdin.take();
        let saved_redirs = env.redirections.clone();
        let saved_sockets = env.socket_fds.clone();
        let saved_descriptors = env.descriptors.clone();
        // `{ ...; } 2>&1 | consumer`: the pipe is a channel the
        // body writes as fd 1 before the group's redirections
        // apply, and the consumer then reads as fd 0.
        let pipe = |stage, read| crate::flow::Redirection {
            role: crate::flow::RedirRole::Channel {
                stage,
                read,
                write: !read,
            },
            fd: Descriptor::Number(u32::from(!read)),
            dup: None,
            both: false,
            read_effect: None,
            write_effect: None,
        };
        let channel = parse::items_span(consumer).map(|span| {
            let node = self.span_node(builder, span);
            let stage = builder.pending_flow_stage(FlowStage {
                execution: None,
                effects: Vec::new(),
                bindings: vec![PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: BindEnd::Port(Port::Stdin),
                    to: BindEnd::Port(Port::Stdout),
                }],
                provenance: vec![node],
            }) as u32;
            builder.keep_pending_flow_stage(stage);
            env.redirections.push(pipe(stage, false));
            env.socket_fds.remove(&Descriptor::Number(1));
            // Record the bytes the body writes, so the
            // consumer can read them as a stage would.
            env.channel_bytes
                .borrow_mut()
                .insert(stage, Some(String::new()));
            (stage, node)
        });
        // The body and its consumer are the pipeline's two stages.
        if !consumer.is_empty() {
            builder.push_pipeline_stage(0);
        }
        self.walk(
            builder,
            env,
            std::slice::from_ref(redirect),
            force_conditional,
            walk_depth + 1,
        );
        let redirected =
            env.redirections[saved_redirs.len().min(env.redirections.len())..].to_vec();
        let compound_stdin = env.compound_stdin.take();
        let reads_stdin = matches!(redirect, ShellItem::Pipeline { cmds, .. }
            if cmds.iter().any(|cmd| cmd.redirs.iter().any(|redir|
                redir.named_fd.is_none() && redir.fd.unwrap_or(match redir.kind {
                    RedirKind::Out | RedirKind::Append => 1,
                    _ => 0,
                }) == 0)));
        env.stdin = match &compound_stdin {
            Some((stdin, _)) => Some(stdin.clone()),
            None if reads_stdin => None,
            None => outer_stdin,
        };
        let body_start = builder.effects_len();
        let body_boundaries = builder.boundaries_len();
        let termination = self.walk(
            builder,
            env,
            std::slice::from_ref(body),
            force_conditional,
            walk_depth + 1,
        );
        // Each command the body ran feeds the group's redirection through its
        // own stage. Where the walk stopped short of one (a command it could
        // not name, a saturated budget), that command may have printed there
        // too: the file is also fed by the shell's own output, a port no
        // source is shown to reach.
        if builder.boundaries_len() != body_boundaries
            || self.nest.budget.steps_saturated()
            || self.nest.budget.bytes_saturated()
            || builder.effects_saturated()
            || builder.execution_saturated()
        {
            let bindings = redirected
                .iter()
                .filter_map(|redir| {
                    let port = match redir.fd {
                        Descriptor::Number(1) => Port::Stdout,
                        Descriptor::Number(2) => Port::Stderr,
                        _ => return None,
                    };
                    Some(PortBinding {
                        assurance: effinterp_proto::CausalAssurance::Exact,
                        from: BindEnd::Port(port),
                        to: BindEnd::Effect(redir.write_effect?),
                    })
                })
                .collect::<Vec<_>>();
            if !bindings.is_empty() {
                let node = parse::items_span(std::slice::from_ref(redirect))
                    .map(|span| self.span_node(builder, span));
                let stage = builder.pending_flow_stage(FlowStage {
                    execution: Some(builder.current_execution()),
                    effects: Vec::new(),
                    bindings,
                    provenance: node.into_iter().collect(),
                }) as u32;
                builder.keep_pending_flow_stage(stage);
            }
        }
        if !consumer.is_empty() {
            builder.pop_pipeline_stage();
        }
        env.stdin = None;
        if let Some((_, producers)) = compound_stdin
            && let Some(span) = parse::items_span(items)
        {
            self.wire_code_producers(
                builder,
                span,
                None,
                &producers,
                body_start,
                builder.effects_len(),
                true,
            );
        }
        env.redirections
            .extend(crate::flow::restore_descriptors(&saved_redirs, &redirected));
        for redir in &redirected {
            match saved_sockets.get(&redir.fd) {
                Some(socket) => {
                    env.socket_fds.insert(redir.fd, socket.clone());
                }
                None => {
                    env.socket_fds.remove(&redir.fd);
                }
            }
            match saved_descriptors.get(&redir.fd) {
                Some(content) => {
                    env.descriptors.insert(redir.fd, content.clone());
                }
                None => {
                    env.descriptors.remove(&redir.fd);
                }
            }
        }
        let env = caller;
        let Some((stage, node)) = channel else {
            return termination;
        };
        // The producer's own `exit` ends only its stage.
        if let Some(producer) = producer.as_deref_mut() {
            builder.push_pipeline_stage(0);
            self.finish_deferred(builder, producer);
            builder.pop_pipeline_stage();
        }
        let piped = env
            .channel_bytes
            .borrow()
            .get(&stage)
            .cloned()
            .flatten()
            .map(|bytes| StdinValue {
                paths: None,
                piped: true,
                file: None,
                word: Word::literal(bytes),
                provenance: vec![node],
            });
        if let Some(mut consumer_env) = consumer_entry {
            consumer_env.socket_fds.remove(&Descriptor::Number(0));
            consumer_env.redirections.push(pipe(stage, true));
            consumer_env.stdin = piped;
            builder.push_pipeline_stage(1);
            self.walk(
                builder,
                &mut consumer_env,
                consumer,
                force_conditional,
                walk_depth + 1,
            );
            self.finish_deferred(builder, &mut consumer_env);
            builder.pop_pipeline_stage();
            // The pipeline's status is its last stage's.
            env.status = consumer_env.status;
        } else {
            let stdin_socket = env.socket_fds.remove(&Descriptor::Number(0));
            env.redirections.push(pipe(stage, true));
            env.stdin = piped;
            builder.push_pipeline_stage(1);
            let termination = self.walk(builder, env, consumer, force_conditional, walk_depth + 1);
            builder.pop_pipeline_stage();
            env.redirections.retain(|redir| {
                !matches!(redir.role, crate::flow::RedirRole::Channel {
                    stage: read_stage,
                    read: true,
                    ..
                } if read_stage == stage)
            });
            if let Some(socket) = stdin_socket {
                env.socket_fds.insert(Descriptor::Number(0), socket);
            }
            if termination.is_some() {
                return termination;
            }
        }
        None
    }
}
