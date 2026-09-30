//! Virtual-machine CLIs that execute commands in a remote guest.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionEdgeKind, ExecutionRealm, ProvenanceRef, ResourceExpr, ResourceFamily,
};

use crate::builder::PlanBuilder;
use crate::models::common::{
    arg_effect, arg_node, has_unknown, nest_remote_shell, unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx};
use crate::nest::{Transition, word_resource};
use crate::word::Word;

const REMOTE_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

pub(super) fn remote_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(Vagrant), Box::new(Lima), Box::new(Multipass)]
}

fn unmodeled_subcommand(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: String) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNMODELED_SUBCOMMAND,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: REMOTE_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail),
    });
}

fn unrecoverable_source(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    argument: ProvenanceRef,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: REMOTE_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![model_node, argument],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

fn unresolved_network() -> ResourceExpr {
    ResourceExpr::Unresolved {
        family: ResourceFamily::new("network"),
    }
}

fn ssh_trailing_command(argv: &[Word], mut start: usize) -> usize {
    const VALUE_FLAGS: &[&str] = &[
        "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
        "-P", "-p", "-Q", "-R", "-S", "-W", "-w",
    ];
    while start < argv.len() {
        match argv[start].as_literal() {
            Some(flag) if VALUE_FLAGS.contains(&flag) => start += 2,
            Some(flag) if flag.starts_with('-') && flag.len() > 1 => start += 1,
            _ => break,
        }
    }
    start.min(argv.len())
}

fn nest_remote_source(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    start: usize,
    words: &[Word],
    endpoint: String,
) {
    if words.is_empty() {
        return;
    }
    let argument = arg_node(builder, ctx, start as u32);
    if words.iter().any(has_unknown) {
        unrecoverable_source(
            builder,
            model_node,
            argument,
            "remote command contains an expansion that is not statically recoverable",
        );
        return;
    }
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        words
            .iter()
            .map(Word::render_raw)
            .collect::<Vec<_>>()
            .join(" "),
        endpoint,
    );
}

struct Vagrant;

impl CommandModel for Vagrant {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "hashicorp/vagrant@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["vagrant"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let Some(subcommand) = ctx.argv.get(1).and_then(Word::as_literal) else {
            unmodeled_subcommand(builder, model_node, "unresolved vagrant operation".into());
            return;
        };
        if !matches!(subcommand, "ssh" | "winrm") {
            unmodeled_subcommand(builder, model_node, format!("vagrant {subcommand}"));
            return;
        }

        let mut machine = None;
        let mut command = None;
        let mut trailing = None;
        let mut unknown = Vec::new();
        let mut index = 2;
        while index < ctx.argv.len() {
            match ctx.argv[index].as_literal() {
                Some("-c" | "--command") => {
                    if let Some(value) = ctx.argv.get(index + 1) {
                        command = Some((index + 1, std::slice::from_ref(value)));
                        index += 2;
                    } else {
                        unknown.push((index as u32, ctx.argv[index].render_raw()));
                        index += 1;
                    }
                }
                Some("-p" | "--plain" | "-t" | "--tty" | "-T" | "--no-tty") => index += 1,
                Some("--") => {
                    trailing = Some(ssh_trailing_command(ctx.argv, index + 1));
                    break;
                }
                Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                    unknown.push((index as u32, flag.to_string()));
                    index += 1;
                }
                _ if machine.is_none() => {
                    machine = Some((index, &ctx.argv[index]));
                    index += 1;
                }
                _ => index += 1,
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &REMOTE_DOMAINS, &unknown);

        let endpoint = format!(
            "vagrant:{}",
            machine.map_or_else(|| "default".to_string(), |(_, word)| word.render_raw())
        );
        let connect_index = machine.map_or(1, |(index, _)| index);
        arg_effect(
            builder,
            ctx,
            model_node,
            connect_index as u32,
            "network.connect",
            unresolved_network(),
            Default::default(),
        );
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);

        if let Some((start, words)) = command {
            nest_remote_source(builder, ctx, model_node, start, words, endpoint);
        } else if let Some(start) = trailing {
            nest_remote_source(
                builder,
                ctx,
                model_node,
                start,
                &ctx.argv[start..],
                endpoint,
            );
        }
    }
}

struct Lima;

impl CommandModel for Lima {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "lima-vm/limactl@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["limactl", "lima"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if ctx.argv.first().and_then(Word::as_literal) == Some("lima") {
            nest_remote_exec(
                builder,
                ctx,
                model_node,
                1,
                None,
                "lima:$LIMA_INSTANCE".to_string(),
            );
            return;
        }
        if ctx.argv.get(1).and_then(Word::as_literal) != Some("shell") {
            let detail = ctx.argv.get(1).map_or_else(
                || "limactl".to_string(),
                |word| format!("limactl {}", word.render_raw()),
            );
            unmodeled_subcommand(builder, model_node, detail);
            return;
        }

        let mut workdir = None;
        let mut unknown = Vec::new();
        let mut index = 2;
        while index < ctx.argv.len() {
            match ctx.argv[index].as_literal() {
                Some("--workdir") => {
                    workdir = ctx.argv.get(index + 1).map(Word::render_raw);
                    index += 2;
                }
                Some("--shell") => index += 2,
                Some("--tty") => index += 1,
                Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                    unknown.push((index as u32, flag.to_string()));
                    index += 1;
                }
                _ => break,
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &REMOTE_DOMAINS, &unknown);
        let Some(instance) = ctx.argv.get(index) else {
            return;
        };
        nest_remote_exec(
            builder,
            ctx,
            model_node,
            index + 1,
            workdir.as_deref(),
            format!("lima:{}", instance.render_raw()),
        );
    }
}

struct Multipass;

impl CommandModel for Multipass {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "canonical/multipass@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["multipass"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        match ctx.argv.get(1).and_then(Word::as_literal) {
            Some("shell") => {
                unmodeled_subcommand(builder, model_node, "interactive multipass shell".into());
                return;
            }
            Some("exec") => {}
            Some(subcommand) => {
                unmodeled_subcommand(builder, model_node, format!("multipass {subcommand}"));
                return;
            }
            None => {
                unmodeled_subcommand(builder, model_node, "unresolved multipass operation".into());
                return;
            }
        }

        let mut workdir = None;
        let mut unknown = Vec::new();
        let mut index = 2;
        while index < ctx.argv.len() {
            match ctx.argv[index].as_literal() {
                Some("-d" | "--working-directory") => {
                    workdir = ctx.argv.get(index + 1).map(Word::render_raw);
                    index += 2;
                }
                Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                    unknown.push((index as u32, flag.to_string()));
                    index += 1;
                }
                _ => break,
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &REMOTE_DOMAINS, &unknown);
        let Some(instance) = ctx.argv.get(index) else {
            return;
        };
        let mut command_start = index + 1;
        if ctx.argv.get(command_start).and_then(Word::as_literal) == Some("--") {
            command_start += 1;
        }
        nest_remote_exec(
            builder,
            ctx,
            model_node,
            command_start,
            workdir.as_deref(),
            format!("multipass:{}", instance.render_raw()),
        );
    }
}

fn nest_remote_exec(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    start: usize,
    cwd: Option<&str>,
    endpoint: String,
) {
    let words = &ctx.argv[start.min(ctx.argv.len())..];
    if words.is_empty() {
        return;
    }
    let argument = arg_node(builder, ctx, start as u32);
    let argv_provenance = ctx.argv_provenance_range(builder, start..ctx.argv.len());
    {
        let words: &[Word] = words;
        ctx.nest.nest(
            builder,
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(cwd)
                .stdin(ctx.stdin)
                .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                .argv_provenance(Some(argv_provenance.as_slice()))
                .kind(ExecutionEdgeKind::ContainerRealm)
                .realm(ExecutionRealm::Remote { endpoint }),
            &[model_node, argument],
            ctx.depth,
        )
    };
}
