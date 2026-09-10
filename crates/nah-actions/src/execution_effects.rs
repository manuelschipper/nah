//! Retains interpreted execution and disclosure facts with their modeled payload ports.

use Knowledge::{Known, Unknown};
use nah_proto::action::{EffectKind, InvocationEffect, NetworkDirection, SemanticCode};
use nah_proto::effects::*;

fn fact(graph: &mut EffectGraph, call: CallId, payload: FactPayload) -> FactId {
    let id = FactId(graph.facts.len() as u32);
    graph.facts.push(EffectFact {
        id,
        call,
        realm: Realm::Host,
        certainty: Certainty::Exact,
        modality: Modality::May,
        condition: None,
        occurrences: None,
        payload,
    });
    id
}

fn resource(graph: &mut EffectGraph, kind: ResourceKind, name: Knowledge<String>) -> ResourceId {
    let id = ResourceId(graph.resources.len() as u32);
    graph.resources.push(EffectResource {
        id,
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind,
            details: Unknown,
            provider: Unknown,
            name,
        },
        selection: Selection::Unknown,
        labels: None,
    });
    id
}

fn port(
    graph: &mut EffectGraph,
    call: CallId,
    fact: Option<FactId>,
    kind: PortKind,
) -> OccurrenceId {
    let id = OccurrenceId(graph.occurrences.len() as u32);
    graph.occurrences.push(EffectOccurrence {
        id,
        call,
        fact,
        resource: None,
        port: kind,
        condition: None,
    });
    id
}

fn transfer(graph: &mut EffectGraph, from: OccurrenceId, to: OccurrenceId) {
    graph.relations.push(EffectRelation {
        from,
        to,
        kind: RelationKind::ValueDependence,
        condition: None,
        certainty: Certainty::Exact,
    });
}

/// Stage dataflow ports are semantic summaries, not fabricated syscalls or argv.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_stage(
    graph: &mut EffectGraph,
    effects: &[EffectKind],
    filesystem_start: usize,
    response: bool,
    environment: Option<EnvironmentSelection>,
    credential: Option<(CredentialOperation, DeletionMode)>,
    queries: &[String],
) -> (OccurrenceId, OccurrenceId) {
    let invocation = effects.iter().find_map(|effect| match effect {
        EffectKind::Invocation { invocation } => Some(invocation),
        _ => None,
    });
    let call = CallId(graph.calls.len() as u32);
    if call == CallId(1) {
        graph.gaps.push(EffectGap {
            id: GapId(graph.gaps.len() as u32),
            phase: GapPhase::Projection,
            category: GapCategory::Unmodeled,
            call: CallId(0),
            domain: None,
            code: "payload-group-unavailable".into(),
        });
    }
    graph.calls.push(EffectCall {
        id: call,
        parent: Some(CallId(0)),
        kind: if matches!(invocation, Some(InvocationEffect::CodeExecution { .. })) {
            InvocationKind::VisibleCode
        } else if invocation.is_some_and(|invocation| {
            matches!(
                invocation.input(),
                nah_proto::action::InvocationInput::Native { .. }
            )
        }) {
            InvocationKind::Native
        } else {
            InvocationKind::Argv
        },
        identity: invocation.map_or(Unknown, |invocation| Known(invocation.program().to_owned())),
        input: None,
        cwd: invocation
            .and_then(InvocationEffect::cwd)
            .cloned()
            .map_or(Unknown, Known),
        payload_group: Unknown,
        visibility_ordinal: Unknown,
        coverage: graph.calls[0].coverage,
    });
    let input = port(graph, call, None, PortKind::SemanticInput);
    let output = port(graph, call, None, PortKind::SemanticOutput);
    transfer(graph, input, output);
    let filesystem_end = graph.facts.len();
    for index in filesystem_start..filesystem_end {
        graph.facts[index].call = call;
        let payload = graph.facts[index].payload.clone();
        if let FactPayload::FilesystemAccess {
            operation,
            target,
            recursive,
            ..
        } = payload
        {
            if let FactPayload::FilesystemAccess { purpose, .. } = &mut graph.facts[index].payload {
                *purpose = AccessPurpose::Explicit;
            }
            let occurrence = port(
                graph,
                call,
                Some(graph.facts[index].id),
                if matches!(
                    operation,
                    FilesystemOperation::Read | FilesystemOperation::Move
                ) {
                    PortKind::SemanticOutput
                } else {
                    PortKind::SemanticInput
                },
            );
            if matches!(
                operation,
                FilesystemOperation::Read | FilesystemOperation::Move
            ) {
                transfer(graph, occurrence, output);
            } else {
                transfer(graph, input, occurrence);
            }
            if operation == FilesystemOperation::Read {
                for query in queries {
                    let id = fact(
                        graph,
                        call,
                        FactPayload::FilesystemSearch {
                            target,
                            selection: Selection::Unknown,
                            query: Known(query.clone()),
                            kind: SearchKind::Content,
                            recursive,
                            output: SearchOutput::Content,
                        },
                    );
                    let occurrence = port(graph, call, Some(id), PortKind::SemanticOutput);
                    transfer(graph, occurrence, output);
                }
            }
        }
    }
    if let Some(names) = environment {
        fact(
            graph,
            call,
            FactPayload::EnvironmentAccess {
                names,
                operation: EnvironmentOperation::Read,
                purpose: AccessPurpose::Explicit,
                output: Some(output),
            },
        );
    }
    if let Some((operation, deletion)) = credential {
        let target = resource(graph, ResourceKind::CredentialStore, Unknown);
        let id = fact(
            graph,
            call,
            FactPayload::CredentialAccess {
                target,
                operation,
                deletion,
                workflow: CredentialWorkflow::Ordinary,
                purpose: AccessPurpose::Explicit,
            },
        );
        if operation == CredentialOperation::ReadValue {
            let occurrence = port(graph, call, Some(id), PortKind::SemanticOutput);
            transfer(graph, occurrence, output);
        }
    }
    if response {
        let target = resource(graph, ResourceKind::Endpoint, Unknown);
        fact(
            graph,
            call,
            FactPayload::NetworkAccess {
                operation: NetworkOperation::Download,
                target,
                direction: Known(TransferDirection::Inbound),
                ports: vec![output],
                attached_execution: Unknown,
            },
        );
    }
    for effect in effects {
        match effect {
            EffectKind::Invocation {
                invocation: InvocationEffect::CodeExecution { source, code, .. },
            } => {
                let derivation = if source == &SemanticCode::ENCODED_COMMAND {
                    ExecutionDerivation::Encoded
                } else if source == &SemanticCode::DECODED_EXECUTION {
                    ExecutionDerivation::Decoded
                } else if source == &SemanticCode::SHELL_PATTERN {
                    ExecutionDerivation::PatternSelected
                } else if source == &SemanticCode::UNRESOLVED_COMMAND {
                    ExecutionDerivation::UnresolvedCommand
                } else if source == &SemanticCode::EVALUATED_SHELL {
                    ExecutionDerivation::Evaluated
                } else {
                    ExecutionDerivation::Plain
                };
                let source = if source == &SemanticCode::SHELL_FILE
                    || source == &SemanticCode::INTERPRETER_FILE
                {
                    ExecutionSource::File
                } else if source == &SemanticCode::SHELL_STDIN
                    || source == &SemanticCode::INTERPRETER_STDIN
                {
                    ExecutionSource::Stdin
                } else if source == &SemanticCode::SHELL_INTERACTIVE {
                    ExecutionSource::Interactive
                } else if source == &SemanticCode::SHELL_INLINE
                    || source == &SemanticCode::INTERPRETER_INLINE
                    || source == &SemanticCode::ENCODED_COMMAND
                    || source == &SemanticCode::EVALUATED_SHELL
                {
                    ExecutionSource::Argument
                } else {
                    ExecutionSource::Unknown
                };
                fact(
                    graph,
                    call,
                    FactPayload::ExecutionInput {
                        resource: None,
                        port: Some(input),
                        source,
                        derivation,
                        visible_payload: if code.is_some() {
                            VisiblePayload::Present
                        } else {
                            VisiblePayload::Absent
                        },
                    },
                );
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::DECODE => {
                fact(
                    graph,
                    call,
                    FactPayload::Transform {
                        operation: TransformOperation::Decode,
                        input: Some(input),
                        output: Some(output),
                    },
                );
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::NETWORK_SHELL => {
                fact(
                    graph,
                    call,
                    FactPayload::ExecutionInput {
                        resource: None,
                        port: None,
                        source: ExecutionSource::NetworkAttachment,
                        derivation: ExecutionDerivation::Plain,
                        visible_payload: VisiblePayload::Absent,
                    },
                );
            }
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. },
            } if operation == &SemanticCode::NETWORK_LISTENER => {
                let target = resource(graph, ResourceKind::Endpoint, Unknown);
                fact(
                    graph,
                    call,
                    FactPayload::NetworkAccess {
                        operation: NetworkOperation::Listen,
                        target,
                        direction: Unknown,
                        ports: vec![output],
                        attached_execution: Unknown,
                    },
                );
            }
            EffectKind::Network { direction, host } => {
                let target = resource(
                    graph,
                    ResourceKind::Endpoint,
                    host.clone().map_or(Unknown, Known),
                );
                let direction = match direction {
                    NetworkDirection::Inbound => TransferDirection::Inbound,
                    NetworkDirection::Outbound => TransferDirection::Outbound,
                };
                fact(
                    graph,
                    call,
                    FactPayload::NetworkAccess {
                        operation: NetworkOperation::Transfer,
                        target,
                        direction: Known(direction),
                        ports: vec![input],
                        attached_execution: Unknown,
                    },
                );
            }
            _ => {}
        }
    }
    // Explicit command inputs feed an outbound payload, including upload file arguments.
    // This relation is retained only inside one interpreted operation.
    let uploads = graph.facts.iter().skip(filesystem_end).any(|fact| {
        matches!(
            fact.payload,
            FactPayload::NetworkAccess {
                direction: Known(TransferDirection::Outbound),
                ..
            }
        )
    });
    if uploads {
        let sources = graph
            .occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.call == call
                    && occurrence.fact.is_some()
                    && occurrence.port == PortKind::SemanticOutput
            })
            .map(|occurrence| occurrence.id)
            .collect::<Vec<_>>();
        for source in sources {
            transfer(graph, source, input);
        }
    }
    (input, output)
}
