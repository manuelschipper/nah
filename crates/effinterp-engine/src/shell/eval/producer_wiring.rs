//! Producer wiring: def-use edges from the pending flow values a command's
//! argv words and standard input carry to the effects that consume them,
//! including the request body, header and URL arguments of `curl` and `wget`.

use effinterp_proto::{ExecutionNodeRef, Port};

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, Flow, FlowReason, FlowRef, FlowStage, PortBinding};
use crate::models::{curl_flow_info, wget_flow_info};
use crate::shell::lex::ShellSpan;
use crate::shell::{Converted, Shell};
use crate::word::Word;

impl Shell<'_> {
    /// Wire def-use edges for argv words carrying a produced value. Effects
    /// attributed to an argument consume it directly; other same-execution
    /// effects consume it too, except process identities and code execution.
    /// Curl and wget also bind request-body and header arguments onto their
    /// network effects (those are attributed to the URL) and keep TLS and
    /// cookie-file config arguments off that same-execution fallback.
    pub(super) fn wire_arg_producers(
        &self,
        builder: &mut PlanBuilder,
        span: ShellSpan,
        execution: Option<ExecutionNodeRef>,
        converted: &[Converted],
        eff_start: usize,
        eff_end: usize,
    ) {
        if eff_end <= eff_start {
            return;
        }
        let carrying: Vec<(u32, &Vec<FlowRef>)> = converted
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, c)| !c.producers.is_empty())
            .map(|(n, c)| (n as u32, &c.producers))
            .collect();
        if carrying.is_empty() {
            return;
        }
        // The request flow of each curl/wget this command runs, keyed to its
        // own execution. The direct case is the command itself; the nested
        // cases are the invocations wrappers launch, read from the modeled
        // argv and mapped back to the outer words through the forwarding the
        // wrapper recorded, so no wrapper needs its own peeling rule.
        let requests = request_invocations(builder, converted, execution, eff_start, eff_end);
        let consumes_argument = |effect: u32, argument: u32| {
            // Listings consume the selected environment values, not every wrapper argument.
            if crate::flow::environment_stdout_effect(builder, effect) {
                return false;
            }
            let effect_execution = builder.effect_execution(effect as usize);
            let operation = builder.effect_operation(effect as usize);
            let network = operation.is_some_and(|operation| operation.starts_with("network."));
            // Output paths and local configuration filenames are inputs to the
            // transfer, not bytes it sends. Never bind them onto their
            // request's network effect, even though the transfer depends on
            // the file they name and the request reaches this argument through
            // its own forwarding.
            if network
                && requests.iter().any(|request| {
                    request.execution == effect_execution
                        && (request.config.contains(&argument)
                            || request.output.contains(&argument))
                })
            {
                return false;
            }
            // A direct index match only holds within the invocation whose
            // arguments these are; a descendant reuses the same indices for
            // its own words, so it is reached only through the forwarded
            // provenance that traces back to this argument.
            let direct = builder.effect_has_argument(effect as usize, argument)
                && execution.is_none_or(|execution| effect_execution == Some(execution));
            if direct
                || execution.is_some_and(|execution| {
                    builder.effect_has_forwarded_argument(effect as usize, argument, execution)
                })
            {
                return true;
            }
            // A request's body or header substitution binds to that request's
            // own network effect alone; a second, independent invocation's
            // effect must not consume the first's header or body.
            for request in &requests {
                if request.execution != effect_execution {
                    continue;
                }
                if operation == Some("network.upload") && request.body.contains(&argument)
                    || network && request.headers.contains(&argument)
                {
                    return true;
                }
            }
            // Anything else a substitution reaches is bound only within this
            // command's own execution, never a nested invocation whose own
            // words this argument never became. Request config values
            // (certificates, cookie files) configure the transfer and are
            // never carried by any of its effects; output values still reach
            // the local write they name, excluded above only from the network
            // effect.
            let outer_same_execution =
                !matches!(operation, Some("process.exec" | "process.code_execution"))
                    && execution.is_some_and(|execution| effect_execution == Some(execution));
            let outer_config = requests
                .iter()
                .filter(|request| request.execution == execution)
                .any(|request| request.config.contains(&argument));
            outer_same_execution && !outer_config
        };
        let effects: Vec<u32> = (eff_start as u32..eff_end as u32)
            .filter(|effect| {
                carrying
                    .iter()
                    .any(|(arg, _)| consumes_argument(*effect, *arg))
            })
            .collect();
        if effects.is_empty() {
            return;
        }
        let carrying = carrying
            .into_iter()
            .filter(|(arg, _)| {
                effects
                    .iter()
                    .any(|effect| consumes_argument(*effect, *arg))
            })
            .collect::<Vec<_>>();
        let mut bindings = Vec::new();
        for (arg, _) in &carrying {
            for &e in &effects {
                if consumes_argument(e, *arg) {
                    bindings.push(PortBinding {
                        assurance: effinterp_proto::CausalAssurance::Conservative,
                        from: BindEnd::Port(Port::Arg(*arg)),
                        to: BindEnd::Effect(e),
                    });
                }
            }
        }
        let node = self.span_node(builder, span);
        let consumer = builder.pending_flow_stage(FlowStage {
            execution,
            effects,
            bindings,
            provenance: vec![node],
        });
        for (arg, producers) in carrying {
            for producer in producers {
                builder.pending_flow_edge(Flow {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: producer.clone(),
                    to: FlowRef {
                        stage: consumer as u32,
                        port: Port::Arg(arg),
                    },
                    reason: FlowReason::new("data_flow"),
                    provenance: Vec::new(),
                });
            }
        }
    }

    /// Wire the pending flow values in `producers` to the `process.code_execution`
    /// effects in `eff_start..eff_end`: the values are the code those effects run.
    /// `stdin_code_only` keeps only the effects whose code arrives on standard
    /// input or interactively.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::shell) fn wire_code_producers(
        &self,
        builder: &mut PlanBuilder,
        span: ShellSpan,
        execution: Option<ExecutionNodeRef>,
        producers: &[FlowRef],
        eff_start: usize,
        eff_end: usize,
        stdin_code_only: bool,
    ) {
        if producers.is_empty() {
            return;
        }
        let effects = (eff_start as u32..eff_end as u32)
            .filter(|effect| {
                builder.effect_operation(*effect as usize) == Some("process.code_execution")
                    && (!stdin_code_only
                        || matches!(
                            builder.effect_string_attribute(*effect as usize, "source"),
                            Some("stdin" | "interactive")
                        ))
            })
            .collect::<Vec<_>>();
        if effects.is_empty() {
            return;
        }
        let node = self.span_node(builder, span);
        let mut consumers = Vec::new();
        // Code a launcher's command runs from the stream it was handed
        // (`ssh host bash <<< …` runs the text in the remote shell) arrives
        // through the launcher's standard input, which the launch routes to
        // that command, so the values feed that stream too.
        if execution.is_some()
            && effects
                .iter()
                .any(|effect| builder.effect_execution(*effect as usize) != execution)
        {
            consumers.push((
                builder.pending_flow_stage(FlowStage {
                    execution,
                    effects: Vec::new(),
                    bindings: Vec::new(),
                    provenance: vec![node],
                }),
                Port::Stdin,
            ));
        }
        let bindings = effects
            .iter()
            .map(|effect| PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: BindEnd::Port(Port::Code),
                to: BindEnd::Effect(*effect),
            })
            .collect();
        consumers.push((
            builder.pending_flow_stage(FlowStage {
                execution,
                effects,
                bindings,
                provenance: vec![node],
            }),
            Port::Code,
        ));
        for (consumer, port) in consumers {
            for producer in producers {
                builder.pending_flow_edge(Flow {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: producer.clone(),
                    to: FlowRef {
                        stage: consumer as u32,
                        port: port.clone(),
                    },
                    reason: FlowReason::new("code input"),
                    provenance: Vec::new(),
                });
            }
        }
    }
}

/// One curl/wget invocation's request-flow argument indices, in the outer
/// command's argv, keyed to the execution whose network effects they bind.
struct RequestInvocation {
    execution: Option<ExecutionNodeRef>,
    body: Vec<u32>,
    headers: Vec<u32>,
    config: Vec<u32>,
    output: Vec<u32>,
}

fn request_flow_name(literal: &str) -> Option<&'static str> {
    match literal.rsplit('/').next() {
        Some("curl") => Some("curl"),
        Some("wget") => Some("wget"),
        _ => None,
    }
}

fn request_flow_indices(name: &str, words: &[Word]) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
    match name {
        "wget" => {
            let info = wget_flow_info(words);
            (
                info.body_value_arguments,
                info.header_arguments,
                info.config_arguments,
                info.output_value_arguments,
            )
        }
        _ => {
            let info = curl_flow_info(words);
            (
                info.body_value_arguments,
                info.header_arguments,
                info.config_arguments,
                info.output_value_arguments,
            )
        }
    }
}

/// The curl/wget invocations this command runs: the command itself when it is
/// one, plus every nested invocation a wrapper launched. A nested invocation's
/// indices are read from its own modeled argv and mapped back to the outer
/// words through the forwarding the wrapper recorded, so a body substitution
/// that reaches any of them is bound to that invocation's upload alone.
fn request_invocations(
    builder: &PlanBuilder,
    converted: &[Converted],
    execution: Option<ExecutionNodeRef>,
    eff_start: usize,
    eff_end: usize,
) -> Vec<RequestInvocation> {
    let mut requests = Vec::new();
    if let Some(name) = converted
        .first()
        .and_then(|head| head.word.as_literal())
        .and_then(request_flow_name)
    {
        let words = converted.iter().map(|c| c.word.clone()).collect::<Vec<_>>();
        let (body, headers, config, output) = request_flow_indices(name, &words);
        requests.push(RequestInvocation {
            execution,
            body,
            headers,
            config,
            output,
        });
    }
    // A nested request's indices only map back to the outer words when the
    // outer command has an execution to attribute the forwarding to.
    let Some(outer) = execution else {
        return requests;
    };
    let mut seen = std::collections::BTreeSet::new();
    for effect in eff_start..eff_end {
        if builder.effect_operation(effect) != Some("process.exec") {
            continue;
        }
        let Some(child) = builder.effect_execution(effect) else {
            continue;
        };
        if Some(child) == execution || !seen.insert(child) {
            continue;
        }
        let Some(name) = builder
            .effect_execution_command(effect)
            .and_then(request_flow_name)
        else {
            continue;
        };
        let Some(argv) = builder.execution_argv(child) else {
            continue;
        };
        let words = argv
            .iter()
            .map(|word| Word::literal(word.clone()))
            .collect::<Vec<_>>();
        let (body, headers, config, output) = request_flow_indices(name, &words);
        let map = |indices: Vec<u32>| {
            indices
                .into_iter()
                .filter_map(|index| builder.forwarded_argument_root(effect, index, outer))
                .collect::<Vec<_>>()
        };
        requests.push(RequestInvocation {
            execution: Some(child),
            body: map(body),
            headers: map(headers),
            config: map(config),
            output: map(output),
        });
    }
    requests
}
