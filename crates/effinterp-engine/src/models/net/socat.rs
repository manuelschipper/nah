use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, Effect, Modality, Operation, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_with_value_indices};
use crate::models::common::{
    Attrs, arg_effect, arg_node, code_execution, fs_arg_effect, fs_arg_node,
    opaque_source_with_provenance, program_input_attrs, program_output_attrs,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

use self::address::{
    SOCAT_HANDLERS, SocatEnd, socat_address, socat_address_ends, socat_descriptor_path,
    socat_exec_argv, socat_keyword,
};
use super::socket_handler::{analyze_socket_handler, socket_handler_boundary};

mod address;

/// Socat emits each address effect only in the directions the invocation uses.
pub(super) struct Socat;

/// Where bytes enter or leave socat at one address end.
#[derive(Clone)]
enum SocatSlot {
    Effect(u32),
    Port(effinterp_proto::Port),
}

#[derive(Default)]
struct SocatEnds {
    source: Option<SocatSlot>,
    sink: Option<SocatSlot>,
    attachment: Option<u32>,
}

/// Emit the effects one address end carries in the directions it is used.
fn socat_end_effects(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    end: &SocatEnd,
    source: bool,
    sink: bool,
) -> SocatEnds {
    let mut ends = SocatEnds::default();
    if !source && !sink {
        return ends;
    }
    match end {
        SocatEnd::File {
            word,
            resource,
            readable,
            writable,
            creates_fifo,
        } => {
            // The pipe is the same request `mkfifo` makes, so a later writer
            // of the name feeds this reader. An entry the host already shows
            // there is opened as it is.
            let present = matches!(
                resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } if path.starts_with('/')
                    && matches!(
                        builder.budget().observe_path(path),
                        effinterp_proto::ObservationOutcome::Path(fact)
                            if fact.kind != effinterp_proto::PathKind::Missing
                    )
            );
            if *creates_fifo && !present {
                let arg = fs_arg_node(builder, ctx, index, word);
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Exact,
                    id: Default::default(),
                    operation: Operation::new("filesystem.create"),
                    resource: resource.clone(),
                    attributes: Attrs::from([("fifo".into(), AttrValue::Bool(true))]),
                    modality: Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: Default::default(),
                    provenance: vec![arg, model_node],
                });
            }
            if source && *readable {
                ends.source = fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    word,
                    "filesystem.read",
                    resource.clone(),
                    program_input_attrs(),
                )
                .map(SocatSlot::Effect);
            }
            if sink && *writable {
                ends.sink = fs_arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    word,
                    "filesystem.write",
                    resource.clone(),
                    program_output_attrs(),
                )
                .map(SocatSlot::Effect);
            }
        }
        SocatEnd::Socket {
            resource,
            protocol,
            listen,
            address,
            proxy,
        } => {
            let attributes = BTreeMap::from([
                ("protocol".into(), AttrValue::String((*protocol).into())),
                ("listen".into(), AttrValue::Bool(*listen)),
                ("address".into(), AttrValue::String(address.clone())),
            ]);
            let attachment = arg_effect(
                builder,
                ctx,
                model_node,
                index,
                if *listen {
                    "network.listen"
                } else {
                    "network.connect"
                },
                proxy.clone().unwrap_or_else(|| resource.clone()),
                attributes.clone(),
            );
            if !*listen {
                ends.attachment = attachment;
            }
            // A listener's bind address does not identify its future peer.
            let peer = if *listen {
                unresolved_resource("network")
            } else {
                resource.clone()
            };
            if source {
                ends.source = arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "network.download",
                    peer.clone(),
                    attributes.clone(),
                )
                .map(SocatSlot::Effect);
            }
            if sink {
                ends.sink = arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "network.upload",
                    peer,
                    attributes,
                )
                .map(SocatSlot::Effect);
            }
        }
        SocatEnd::Stdio { reads, writes } => {
            // Standard input is read and standard output and error are written
            // through socat's own streams. Any other direction goes wherever
            // the shell pointed the descriptor (`2<&0`), so the shell binds
            // that access to it.
            let descriptor_access = |builder: &mut PlanBuilder, descriptor: u32, operation| {
                let word = Word::literal(format!("/dev/fd/{descriptor}"));
                let resource = crate::paths::resolve_fs_word_with_cwd(&word, ctx.cwd_resource());
                let attributes = if operation == "filesystem.read" {
                    program_input_attrs()
                } else {
                    program_output_attrs()
                };
                fs_arg_effect(
                    builder, ctx, model_node, index, &word, operation, resource, attributes,
                )
                .map(SocatSlot::Effect)
            };
            if source {
                ends.source = match reads {
                    Some(0) => Some(SocatSlot::Port(effinterp_proto::Port::Stdin)),
                    Some(descriptor) => descriptor_access(builder, *descriptor, "filesystem.read"),
                    None => None,
                };
            }
            if sink {
                ends.sink = match writes {
                    Some(1) => Some(SocatSlot::Port(effinterp_proto::Port::Stdout)),
                    Some(2) => Some(SocatSlot::Port(effinterp_proto::Port::Stderr)),
                    Some(descriptor) => descriptor_access(builder, *descriptor, "filesystem.write"),
                    None => None,
                };
            }
        }
        SocatEnd::Handler { .. } => {}
    }
    ends
}

impl CommandModel for Socat {
    fn id(&self) -> &'static str {
        "network/socat@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["socat"]
    }
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn descriptor_operands(&self, argv: &[Word]) -> Vec<(u32, Word)> {
        argv.iter()
            .enumerate()
            .flat_map(|(index, word)| {
                socat_address_ends(word)
                    .into_iter()
                    .filter_map(move |end| Some((index as u32, socat_descriptor_path(&end)?)))
            })
            .collect()
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let parsed = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                value_flags: &[],
                known_flags: &["-u", "-U", "-d", "-h", "-V"],
                allow_abbreviation: false,
            },
            true,
        );
        if parsed.has(&["-h", "-V"]) {
            return;
        }
        if !parsed.unknown_flags.is_empty()
            || parsed
                .flags
                .iter()
                .any(|flag| ctx.argv[flag.index as usize].literal_prefix().contains('='))
            || parsed.has(&["-u"]) && parsed.has(&["-U"])
            || parsed.operands.len() != 2
        {
            socket_handler_boundary(
                builder,
                &[model_node],
                "socat options or address count are unmodeled",
            );
            return;
        }
        let mut addresses = Vec::new();
        for (index, word) in &parsed.operands {
            match socat_address(word, ctx) {
                Ok(address) => addresses.push((*index, address)),
                Err(detail) => {
                    let argument = arg_node(builder, ctx, *index);
                    if word.as_literal().is_none()
                        && socat_keyword(word.literal_prefix(), SOCAT_HANDLERS.into_iter())
                            .is_some()
                    {
                        code_execution(
                            effinterp_proto::RequestAssurance::Conservative,
                            builder,
                            ctx,
                            model_node,
                            Some(*index),
                            "argument",
                            Default::default(),
                        );
                        opaque_source_with_provenance(
                            builder,
                            &[model_node, argument],
                            &["environment", "filesystem", "network", "process"],
                            detail,
                        );
                    } else {
                        socket_handler_boundary(builder, &[model_node, argument], detail);
                    }
                    return;
                }
            }
        }
        // `-u` keeps only address 1 -> address 2, `-U` only the reverse.
        let unidirectional = parsed.has(&["-u"]);
        let reversed = parsed.has(&["-U"]);
        let feeds = [!reversed, !unidirectional];
        let drains = [!unidirectional, !reversed];

        let handlers = addresses
            .iter()
            .enumerate()
            .filter(|(_, (_, address))| {
                matches!(address.read, SocatEnd::Handler { .. })
                    || matches!(address.write, SocatEnd::Handler { .. })
            })
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        if handlers.len() > 1 {
            socket_handler_boundary(
                builder,
                &[model_node],
                "socat relays between two handlers are unmodeled",
            );
            return;
        }

        let mut ends: Vec<SocatEnds> = Vec::new();
        for (position, (index, address)) in addresses.iter().enumerate() {
            if address.dual {
                let mut read = socat_end_effects(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &address.read,
                    feeds[position],
                    false,
                );
                let write = socat_end_effects(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &address.write,
                    false,
                    drains[position],
                );
                read.sink = write.sink;
                ends.push(read);
            } else {
                ends.push(socat_end_effects(
                    builder,
                    ctx,
                    model_node,
                    *index,
                    &address.read,
                    feeds[position],
                    drains[position],
                ));
            }
        }

        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);

        // A handler keeps both of its descriptors under `-u` and `-U`; the
        // flags only stop socat relaying one direction, so the unused one
        // carries no bytes and the ports below stay bound in the direction
        // the flags kept.
        if let [position] = handlers[..] {
            let (index, address) = &addresses[position];
            let SocatEnd::Handler {
                shell,
                command,
                stderr,
                chdir,
            } = &address.read
            else {
                return;
            };
            let cwd = match (chdir, ctx.cwd) {
                (Some(dir), Some(cwd)) => Some(crate::paths::join_cwd(cwd, dir)),
                (Some(dir), None) if dir.starts_with('/') => Some(dir.clone()),
                (Some(_), None) => None,
                (None, cwd) => cwd.map(str::to_string),
            };
            // The handler's script source resolves under the same chdir; an
            // unknown base stays unknown rather than finding the parent's file.
            let runtime_cwd = match (chdir, ctx.runtime_cwd) {
                (Some(dir), Some(base)) => Some(crate::paths::join_cwd(base, dir)),
                (Some(dir), None) if dir.starts_with('/') => Some(dir.clone()),
                (Some(_), None) => None,
                (None, base) => base.map(str::to_string),
            };
            let other = 1 - position;
            let argument = arg_node(builder, ctx, *index);
            // A `SYSTEM`/`SHELL` command that is a lone shell binary launches an
            // interactive shell on the connection, so model it through the shell
            // program directly (as `EXEC` does) rather than as a script whose
            // only line names that binary.
            let lone_shell = socat_exec_argv(command)
                .is_some_and(|argv| argv.len() == 1 && is_shell_program(&argv[0]));
            // A shell handler whose program the handler's own shell computes
            // (`SYSTEM:'$CMD'`) runs code this analysis cannot read, attached
            // to the connection like any shell socat starts.
            let dynamic = *shell
                && socat_exec_argv(command)
                    .and_then(|argv| argv.into_iter().next())
                    .is_some_and(|program| program.contains(['$', '`']));
            let subject = if dynamic {
                effinterp_proto::Subject::Exec {
                    argv: vec!["sh".into()],
                    cwd: cwd.clone(),
                    context: Default::default(),
                }
            } else if *shell && !lone_shell {
                effinterp_proto::Subject::Shell {
                    source: command.clone(),
                    cwd: cwd.clone(),
                    context: Default::default(),
                }
            } else {
                let Some(argv) = socat_exec_argv(command) else {
                    socket_handler_boundary(
                        builder,
                        &[model_node, argument],
                        "socat EXEC command quoting is not recoverable",
                    );
                    return;
                };
                if argv.is_empty() {
                    return;
                }
                effinterp_proto::Subject::Exec {
                    argv,
                    cwd: cwd.clone(),
                    context: Default::default(),
                }
            };
            // A `SYSTEM`/`SHELL` handler always runs `sh -c`, and an `EXEC`
            // handler that runs a shell binary attaches one too: in both the
            // connection's own bytes are the shell's input.
            let attached_shell = *shell
                || matches!(
                    &subject,
                    effinterp_proto::Subject::Exec { argv, .. }
                        if argv.first().is_some_and(|program| is_shell_program(program))
                );
            // Under `-u`/`-U` the connection may only receive the handler's
            // output; then its bytes never reach the shell's input.
            let input = (attached_shell && feeds[other])
                .then_some(ends[other].attachment)
                .flatten()
                .or_else(|| match &ends[other].source {
                    Some(SocatSlot::Effect(effect)) => Some(*effect),
                    _ => None,
                });
            let output = match &ends[other].sink {
                Some(SocatSlot::Effect(effect)) => Some(*effect),
                _ => None,
            };
            analyze_socket_handler(
                builder,
                ctx,
                &[model_node, argument],
                subject,
                input,
                output,
                BTreeMap::new(),
                *stderr,
                runtime_cwd.as_deref(),
            );
            if dynamic {
                let authored = builder.source_from_subject(ctx.scope);
                let attributes = builder.computed_command_attributes(authored, argument);
                code_execution(
                    effinterp_proto::RequestAssurance::Exact,
                    builder,
                    ctx,
                    model_node,
                    Some(*index),
                    "argument",
                    attributes,
                );
            }
            return;
        }

        // Without a handler socat relays bytes between the two addresses.
        let mut bindings = Vec::new();
        let mut effects = Vec::new();
        for (from, to) in [(0usize, 1usize), (1, 0)] {
            let (Some(source), Some(sink)) = (ends[from].source.clone(), ends[to].sink.clone())
            else {
                continue;
            };
            bindings.push(crate::flow::PortBinding {
                assurance: if builder.execution_is_exact(builder.current_execution())
                    && ctx.argv.iter().all(|word| word.as_literal().is_some())
                {
                    effinterp_proto::CausalAssurance::Exact
                } else {
                    effinterp_proto::CausalAssurance::Conservative
                },
                from: socat_bind_end(&source),
                to: socat_bind_end(&sink),
            });
            for slot in [&source, &sink] {
                if let SocatSlot::Effect(effect) = slot {
                    effects.push(*effect);
                }
            }
        }
        if bindings.is_empty() {
            return;
        }
        effects.sort_unstable();
        effects.dedup();
        builder.flow_stage(crate::flow::FlowStage {
            execution: Some(builder.current_execution()),
            effects,
            bindings,
            provenance: vec![model_node],
        });
    }
}

fn socat_bind_end(slot: &SocatSlot) -> crate::flow::BindEnd {
    match slot {
        SocatSlot::Effect(effect) => crate::flow::BindEnd::Effect(*effect),
        SocatSlot::Port(port) => crate::flow::BindEnd::Port(port.clone()),
    }
}

/// A program name whose basename is a POSIX shell, so attaching a network
/// connection to it hands the peer an interactive shell.
fn is_shell_program(program: &str) -> bool {
    matches!(
        program.rsplit('/').next(),
        Some("sh" | "bash" | "dash" | "zsh" | "ash" | "ksh" | "mksh")
    )
}
