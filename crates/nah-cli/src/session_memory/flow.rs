//! Where content flows within one call, read from the engine's causal graph:
//! which effects' bytes reach which others, an interpreter's program, the
//! call's own output or the network. Only edges that carry content are
//! followed (a value dependency, a transfer, an alias); control, launch and
//! containment edges carry none.

use std::collections::BTreeSet;

use nah_proto::effinterp_proto::{CausalReason, OccurrenceKind, Plan, Port};

enum Node {
    Port { port: Port, execution: Option<u32> },
    Effect { operation: String },
    Other,
}

pub(super) struct Flow {
    nodes: Vec<Node>,
    out: Vec<Vec<usize>>,
    /// The occurrence of each plan effect, where the graph binds one.
    effect_node: Vec<Option<usize>>,
    /// Executions that run a selected program: what reaches their code port
    /// is that program.
    interpreters: BTreeSet<u32>,
    entry: u32,
}

impl Flow {
    pub(super) fn of(plan: &Plan) -> Self {
        let mut flow = Flow {
            nodes: Vec::new(),
            out: Vec::new(),
            effect_node: vec![None; plan.effects.len()],
            interpreters: plan
                .execution_graph
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.input.is_some())
                .map(|(index, _)| index as u32)
                .collect(),
            entry: plan.execution_graph.entry.0,
        };
        let Some(graph) = &plan.causality.graph else {
            return flow;
        };
        let ids: std::collections::BTreeMap<_, _> = graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (&node.id, index))
            .collect();
        for node in &graph.nodes {
            let execution = node.execution.map(|execution| execution.0);
            flow.nodes.push(match &node.occurrence {
                OccurrenceKind::Port { port } => Node::Port {
                    port: port.clone(),
                    execution,
                },
                OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    attributes,
                } => {
                    // The first unbound effect the occurrence states.
                    if let Some(effect) =
                        plan.effects.iter().enumerate().position(|(index, effect)| {
                            flow.effect_node[index].is_none()
                                && effect.operation == *operation
                                && effect.resource == *resource
                                && effect.attributes == *attributes
                                && Some(effect.execution) == node.execution
                        })
                    {
                        flow.effect_node[effect] = Some(flow.nodes.len());
                    }
                    Node::Effect {
                        operation: operation.as_str().to_owned(),
                    }
                }
                _ => Node::Other,
            });
        }
        flow.out = vec![Vec::new(); flow.nodes.len()];
        for edge in &graph.edges {
            if matches!(
                edge.reason,
                CausalReason::ValueDependency
                    | CausalReason::ResourceTransfer
                    | CausalReason::Alias
            ) && let (Some(from), Some(to)) = (ids.get(&edge.from), ids.get(&edge.to))
            {
                flow.out[*from].push(*to);
            }
        }
        flow
    }

    /// Every occurrence the content of `effects` reaches, themselves
    /// included.
    fn reached(&self, effects: impl IntoIterator<Item = usize>) -> BTreeSet<usize> {
        let mut seen = BTreeSet::new();
        let mut queue: Vec<usize> = effects
            .into_iter()
            .filter_map(|effect| self.effect_node.get(effect).copied().flatten())
            .collect();
        while let Some(node) = queue.pop() {
            if seen.insert(node) {
                queue.extend(&self.out[node]);
            }
        }
        seen
    }

    /// Whether the effect's content reaches an interpreter as its program:
    /// code an interpreter executes, or the code port of an execution that
    /// runs a selected program. A program's own code port also takes its
    /// arguments, so reaching it alone proves nothing.
    pub(super) fn reaches_program(&self, effect: usize) -> bool {
        self.reached([effect])
            .into_iter()
            .any(|node| match &self.nodes[node] {
                Node::Effect { operation } => operation == "process.code_execution",
                Node::Port {
                    port: Port::Code,
                    execution: Some(execution),
                } => self.interpreters.contains(execution),
                _ => false,
            })
    }

    /// Whether the effect's content reaches the call's own output, which
    /// the agent reads.
    pub(super) fn reaches_output(&self, effect: usize) -> bool {
        self.reached([effect]).into_iter().any(|node| {
            matches!(
                &self.nodes[node],
                Node::Port { port: Port::Stdout | Port::Stderr, execution: Some(execution) }
                    if *execution == self.entry
            )
        })
    }

    /// Whether the content of any of `effects` reaches a network send.
    pub(super) fn reaches_network(&self, effects: &[usize]) -> bool {
        self.reached(effects.iter().copied())
            .into_iter()
            .any(|node| match &self.nodes[node] {
                Node::Port {
                    port: Port::HttpRequestBody,
                    ..
                } => true,
                Node::Effect { operation } => {
                    operation.starts_with("network.") && operation != "network.listen"
                }
                _ => false,
            })
    }

    /// The plan effects among `targets` that the content of any of
    /// `sources` reaches.
    pub(super) fn reached_effects(&self, sources: &[usize], targets: &[usize]) -> Vec<usize> {
        let reached = self.reached(sources.iter().copied());
        targets
            .iter()
            .copied()
            .filter(|target| {
                !sources.contains(target)
                    && self
                        .effect_node
                        .get(*target)
                        .copied()
                        .flatten()
                        .is_some_and(|node| reached.contains(&node))
            })
            .collect()
    }
}
