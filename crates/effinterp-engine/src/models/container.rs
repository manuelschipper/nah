//! Container runtimes: `docker`/`podman`. `docker exec` runs a
//! command inside a container — that command is nested and its effects
//! compose into the plan (the design's `docker exec postgres -> psql -> SQL`
//! chain). Container operations use a small `container.*` taxonomy targeting
//! a typed `Container` identity; unknown subcommands stay opaque.

use crate::models::args::{
    DOCKER_BUILD, DOCKER_COMPOSE_EXEC, DOCKER_COMPOSE_RUN, DOCKER_EXEC, DOCKER_RUN, FlagSpec,
    Scanned, inner_start, scan, strip_literal_prefix,
};

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance,
    ContainerStorage, CoverageLevel, Domain, Effect, ExecutionEdgeKind, Modality, Operation, Port,
    ProvenanceRef, ResourceExpr, ResourceFamily, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args;
use crate::models::common::{
    Attrs, arg_effect, arg_node, complete_list, fs_arg_effect, fs_arg_node, operand_effect,
    unrecognized_arguments_boundary,
};
use crate::models::{CommandModel, InvocationCtx, ModelBindingEnd, ModelCausalBinding};
use crate::nest::{Transition, word_resource};
use crate::paths::resolve_fs_word;
use crate::resource_transfer::TransferBinding;
use crate::word::{Word, WordPart};
use effinterp_model_schema::EffectSelection;

pub(super) fn container_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(Docker)]
}

pub(super) fn with_lifecycle(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(Nerdctl { owner })
}

struct Nerdctl {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for Nerdctl {
    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model: ProvenanceRef) {
        match ctx.argv.get(1).and_then(Word::as_literal) {
            Some(sub @ ("stop" | "kill" | "restart" | "pause")) => {
                builder.declare_coverage(Domain::new("container"), CoverageLevel::Full);
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                Docker.lifecycle(builder, ctx, model, 2, sub);
            }
            _ => self.owner.apply(builder, ctx, model),
        }
    }
}

const DOMAINS: [&str; 4] = ["container", "filesystem", "network", "process"];
const ROOT_VALUE_FLAGS: [&str; 12] = [
    "-H",
    "--host",
    "-c",
    "--context",
    "--connection",
    "--url",
    "--config",
    "-l",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
];

/// docker / podman: a compatible CLI surface.
struct Docker;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Run,
    Create,
    Compose,
}

impl CommandModel for Docker {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "docker/cli@v6"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["docker", "podman", "docker-compose", "podman-compose"]
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        if !ps_outputs_all_running(argv) {
            return Vec::new();
        }
        vec![ModelCausalBinding {
            assurance: CausalAssurance::Exact,
            from: ModelBindingEnd::Effect {
                operation: "container.resource.read".into(),
                selection: EffectSelection::All,
            },
            to: ModelBindingEnd::Port(Port::Stdout),
        }]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("container"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);

        if ctx
            .argv
            .first()
            .and_then(crate::exec::program_name)
            .is_some_and(|command| matches!(command, "docker-compose" | "podman-compose"))
        {
            self.compose(builder, ctx, model_node, 1);
            return;
        }

        // Skip global options preceding the subcommand.
        let (i, _) = inner_start(ctx.argv, 1, &ROOT_VALUE_FLAGS, false);
        // `--` ends option parsing for the root command, which takes no
        // operands of its own: the words after it are not a subcommand, so
        // the invocation names no operation this model can decide.
        if ctx.argv[1..i]
            .iter()
            .any(|word| word.as_literal() == Some("--"))
        {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some("option terminator before a subcommand".into()),
            });
            return;
        }
        let Some((sub_index, sub)) = ctx
            .argv
            .get(i)
            .and_then(Word::as_literal)
            .map(|s| (i, s.to_string()))
        else {
            return;
        };
        if matches!(
            sub.as_str(),
            "system"
                | "volume"
                | "machine"
                | "compose"
                | "ps"
                | "stop"
                | "kill"
                | "restart"
                | "pause"
        ) {
            let global = scan_options(
                builder,
                model_node,
                &ctx.argv[..sub_index],
                0,
                &FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &ROOT_VALUE_FLAGS,
                    known_flags: &[
                        "--help",
                        "-h",
                        "--version",
                        "-v",
                        "--tls",
                        "--tlsverify",
                        "-D",
                        "--debug",
                    ],
                },
            );
            // Podman's `--connection` and `--url` select a remote service, and
            // its remote client refuses the local-only `system reset`.
            if !global.unknown_flags.is_empty()
                || !global.operands.is_empty()
                || global.has(&["--help", "-h", "--version", "-v"])
                || runtime(ctx) != "podman" && global.has(&["--connection", "--url"])
                || runtime(ctx) == "podman"
                    && sub == "system"
                    && ctx.argv.get(sub_index + 1).and_then(Word::as_literal) == Some("reset")
                    && global.has(&["--connection", "--url"])
            {
                return;
            }
        }
        if matches!(
            sub.as_str(),
            "push"
                | "pull"
                | "buildx"
                | "exec"
                | "run"
                | "create"
                | "cp"
                | "build"
                | "rm"
                | "kill"
                | "stop"
                | "start"
                | "restart"
                | "pause"
                | "unpause"
                | "ps"
        ) || (sub == "image"
            && ctx.argv.get(sub_index + 1).and_then(Word::as_literal) == Some("push"))
        {
            daemon_transport(builder, ctx, model_node, i);
        }
        // Docker registers `--help` on every command, so a disabled help
        // option may sit between a command group and its verb.
        let mut verb_index = sub_index + 1;
        if runtime(ctx) == "docker" && matches!(sub.as_str(), "system" | "volume") {
            while let Some(text) = ctx.argv.get(verb_index).and_then(Word::as_literal) {
                match text.strip_prefix("--help") {
                    Some("" | "=1" | "=t" | "=T" | "=TRUE" | "=true" | "=True") => return,
                    Some("=0" | "=f" | "=F" | "=FALSE" | "=false" | "=False") => verb_index += 1,
                    _ => break,
                }
            }
        }
        let verb = ctx.argv.get(verb_index).and_then(Word::as_literal);
        match sub.as_str() {
            "machine" if runtime(ctx) == "podman" && verb == Some("reset") => {
                self.cleanup(builder, ctx, model_node, sub_index, verb_index, &sub);
            }
            "volume" if runtime(ctx) == "docker" && matches!(verb, Some("rm" | "remove")) => {
                self.volume_remove(builder, ctx, model_node, verb_index);
            }
            "system" | "volume"
                if verb == Some("prune")
                    || sub == "system" && runtime(ctx) == "podman" && verb == Some("reset") =>
            {
                self.cleanup(builder, ctx, model_node, sub_index, verb_index, &sub);
            }
            "push" => super::artifact::docker_push(builder, ctx, model_node, sub_index + 1),
            "image" if ctx.argv.get(sub_index + 1).and_then(Word::as_literal) == Some("push") => {
                super::artifact::docker_push(builder, ctx, model_node, sub_index + 2)
            }
            "ps" if ps_outputs_all_running(ctx.argv) => {
                self.list_running(builder, ctx, model_node, sub_index)
            }
            "pull" => self.image_network(builder, ctx, model_node, sub_index, "network.download"),
            "image"
                if matches!(
                    ctx.argv.get(sub_index + 1).and_then(Word::as_literal),
                    Some("inspect" | "ls")
                ) => {}
            "buildx" if ctx.argv.get(sub_index + 1).and_then(Word::as_literal) == Some("build") => {
                self.build(builder, ctx, model_node, sub_index + 2, false);
            }
            "buildx"
                if ctx.argv.get(sub_index + 1).and_then(Word::as_literal) == Some("imagetools")
                    && matches!(
                        ctx.argv.get(sub_index + 2).and_then(Word::as_literal),
                        Some("create" | "inspect")
                    ) =>
            {
                let operation = if ctx.argv[sub_index + 2].as_literal() == Some("create") {
                    "network.upload"
                } else {
                    "network.request"
                };
                self.image_network(builder, ctx, model_node, sub_index + 2, operation);
            }
            "compose" => self.compose(builder, ctx, model_node, sub_index + 1),
            "exec" => self.exec(builder, ctx, model_node, sub_index + 1, false),
            "run" => self.run(builder, ctx, model_node, sub_index + 1, RunMode::Run),
            "create" => self.run(builder, ctx, model_node, sub_index + 1, RunMode::Create),
            "cp" => self.cp(builder, ctx, model_node, sub_index + 1),
            "build" => self.build(builder, ctx, model_node, sub_index + 1, false),
            "rm" | "kill" | "stop" | "start" | "restart" | "pause" | "unpause" => {
                self.lifecycle(builder, ctx, model_node, sub_index + 1, &sub)
            }
            other => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNMODELED_SUBCOMMAND,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(format!("docker {other}")),
                });
            }
        }
    }
}

impl Docker {
    fn volume_remove(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
    ) {
        let parsed = scan_options(
            builder,
            model_node,
            &ctx.argv[start..],
            start,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &[],
                known_flags: &["--force", "-f", "--help", "-h"],
            },
        );
        if !parsed.unknown_flags.is_empty() || parsed.operands.is_empty() {
            return;
        }
        let mut help = false;
        for flag in &parsed.flags {
            let enabled = match ctx.argv[flag.index as usize]
                .as_literal()
                .and_then(|text| text.split_once('='))
            {
                None | Some((_, "1" | "t" | "T" | "TRUE" | "true" | "True")) => true,
                Some((_, "0" | "f" | "F" | "FALSE" | "false" | "False")) => false,
                _ => {
                    unrecognized_arguments_boundary(
                        builder,
                        model_node,
                        &DOMAINS,
                        &[(flag.index, ctx.argv[flag.index as usize].render_raw())],
                    );
                    return;
                }
            };
            if matches!(flag.name, "--help" | "-h") {
                help = enabled;
            }
        }
        if help {
            return;
        }
        daemon_transport(builder, ctx, model_node, start - 1);
        for (index, word) in parsed.operands {
            let mut attributes = BTreeMap::from([
                ("runtime".into(), AttrValue::String("docker".into())),
                ("scope".into(), AttrValue::String("volume".into())),
                ("action".into(), AttrValue::String("rm".into())),
                ("all".into(), AttrValue::Bool(false)),
            ]);
            if let Some(name) = word.as_literal() {
                attributes.insert("volume".into(), AttrValue::String(name.into()));
            }
            // A volume name is not a container name or a host filesystem path.
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "container.remove",
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new("container"),
                },
                attributes,
            );
        }
    }

    fn cleanup(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        sub_index: usize,
        verb_index: usize,
        scope: &str,
    ) {
        let action = ctx.argv[verb_index].as_literal().unwrap();
        // Each runtime documents its own cleanup option surface; a preview and a
        // filter narrow the selection instead of leaving the command unmodeled.
        let podman = runtime(ctx) == "podman";
        let flags: &[&str] = match (scope, action, podman) {
            (_, "reset", _) => &["--force", "-f", "--help", "-h"],
            // Podman v4.3 prunes every unused volume without `--all`, and later
            // releases prune every unused volume with it. The installed release
            // is not established, so either form sweeps the whole inventory.
            ("volume", _, true) => &["--all", "-a", "--dry-run", "--force", "-f", "--help", "-h"],
            ("volume", _, false) => &["--all", "-a", "--force", "-f", "--help", "-h"],
            (_, _, true) => &[
                "--all",
                "-a",
                "--build",
                "--external",
                "--force",
                "-f",
                "--volumes",
                "--help",
                "-h",
            ],
            (_, _, false) => &["--all", "-a", "--force", "-f", "--volumes", "--help", "-h"],
        };
        let value_flags: &[&str] = if action == "reset" {
            &[]
        } else {
            &["--filter"]
        };
        let argv: Vec<Word> = ctx.argv[verb_index..]
            .iter()
            .map(|word| {
                if let Some((name, value)) =
                    word.as_literal().and_then(|value| value.split_once('='))
                {
                    let long = match name {
                        "-f" => Some("--force"),
                        "-a" if action == "prune" => Some("--all"),
                        "-h" => Some("--help"),
                        _ => None,
                    };
                    if let Some(long) = long {
                        return Word::literal(format!("{long}={value}"));
                    }
                    // In a cluster of boolean shorthands only the last takes the
                    // value; every option here defaults off, so a false one is
                    // the same as an absent one.
                    if name.len() > 2
                        && !name.starts_with("--")
                        && name[1..]
                            .chars()
                            .all(|short| flags.contains(&format!("-{short}").as_str()))
                    {
                        match value {
                            "1" | "t" | "T" | "TRUE" | "true" | "True" => {
                                return Word::literal(name);
                            }
                            "0" | "f" | "F" | "FALSE" | "false" | "False" => {
                                return Word::literal(&name[..name.len() - 1]);
                            }
                            _ => {}
                        }
                    }
                }
                word.clone()
            })
            .collect();
        let parsed = scan_options(
            builder,
            model_node,
            &argv,
            verb_index,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags,
                known_flags: flags,
            },
        );
        if !parsed.operands.is_empty() || !parsed.unknown_flags.is_empty() {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!(
                    "{} {scope} {action}: operands and selection/global options are unmodeled",
                    runtime(ctx)
                )),
            });
            return;
        }
        // `--filter` restricts the sweep to the objects matching a predicate the
        // runtime evaluates against live labels and ages. The cleanup then takes
        // a subset the invocation does not name, not the scope's inventory.
        let filtered = parsed.has(&["--filter"]);
        let mut selected = BTreeMap::new();
        for flag in &parsed.flags {
            if value_flags.contains(&flag.name) {
                continue;
            }
            let name = match flag.name {
                "-a" => "--all",
                "-f" => "--force",
                "-h" => "--help",
                name => name,
            };
            let enabled = match argv[flag.index as usize - verb_index]
                .as_literal()
                .and_then(|text| text.split_once('='))
            {
                None | Some((_, "1" | "t" | "T" | "TRUE" | "true" | "True")) => true,
                Some((_, "0" | "f" | "F" | "FALSE" | "false" | "False")) => false,
                _ => {
                    unrecognized_arguments_boundary(
                        builder,
                        model_node,
                        &DOMAINS,
                        &[(flag.index, ctx.argv[flag.index as usize].render_raw())],
                    );
                    return;
                }
            };
            selected.insert(name, enabled);
        }
        if selected.get("--help") == Some(&true) {
            return;
        }
        let mut attributes = BTreeMap::from([
            ("runtime".into(), AttrValue::String(runtime(ctx))),
            ("active".into(), AttrValue::Bool(true)),
            ("dry_run".into(), AttrValue::Bool(false)),
            ("mode".into(), AttrValue::String(action.into())),
            ("scope".into(), AttrValue::String(scope.into())),
            ("action".into(), AttrValue::String(action.into())),
            ("reset".into(), AttrValue::Bool(action == "reset")),
            ("help".into(), AttrValue::Bool(false)),
            (
                "all".into(),
                AttrValue::Bool(
                    !filtered
                        && (action == "reset"
                            || podman && scope == "volume"
                            || selected.get("--all") == Some(&true)),
                ),
            ),
        ]);
        // Both reset entrypoints remove the runtime's complete managed state.
        // A machine reset includes every VM, disk and configuration rather than
        // selecting one machine or one volume.
        if scope == "machine" && action == "reset" {
            attributes.insert("scope".into(), AttrValue::String("system".into()));
        }
        if !filtered {
            attributes.insert(
                "volumes".into(),
                AttrValue::Bool(
                    scope == "volume"
                        || action == "reset"
                        || selected.get("--volumes") == Some(&true),
                ),
            );
        }
        if filtered {
            attributes.insert("selection".into(), AttrValue::String("filtered".into()));
        }
        if scope != "machine" {
            daemon_transport(builder, ctx, model_node, sub_index);
        }
        // A preview reports the selection the runtime would prune; it removes nothing.
        if selected.get("--dry-run") != Some(&true) {
            arg_effect(
                builder,
                ctx,
                model_node,
                verb_index as u32,
                "container.remove",
                if filtered {
                    // A filtered sweep names no member of the runtime inventory.
                    ResourceExpr::Unresolved {
                        family: ResourceFamily::new("container"),
                    }
                } else {
                    ResourceExpr::Pattern {
                        pattern: effinterp_proto::ResourcePattern::Container {
                            runtime: effinterp_proto::Field::Exact {
                                value: runtime(ctx),
                            },
                            name_glob: None,
                            image_glob: None,
                        },
                    }
                },
                attributes,
            );
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::LIVE_INVENTORY,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("container"), Domain::new("filesystem")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "container cleanup selects runtime-managed objects and storage paths".into(),
            ),
        });
    }

    fn list_running(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        sub_index: usize,
    ) {
        arg_effect(
            builder,
            ctx,
            model_node,
            sub_index as u32,
            "container.resource.read",
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::Container {
                    runtime: effinterp_proto::Field::Exact {
                        value: runtime(ctx),
                    },
                    name_glob: Some("*".into()),
                    image_glob: None,
                },
            },
            Attrs::from([
                ("selection".into(), AttrValue::String("running".into())),
                ("all".into(), AttrValue::Bool(true)),
            ]),
        );
    }

    fn compose(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
    ) {
        let global_value = [
            "-f",
            "--file",
            "-p",
            "--project-name",
            "--project-directory",
            "--env-file",
            "--profile",
            "--parallel",
            "--progress",
            "--ansi",
        ];
        let (sub_index, _) = inner_start(ctx.argv, start, &global_value, false);
        if matches!(
            ctx.argv.get(sub_index).and_then(Word::as_literal),
            Some("exec" | "run" | "down" | "rm" | "up" | "build")
        ) {
            daemon_transport(builder, ctx, model_node, start.saturating_sub(1).max(1));
        }
        match ctx.argv.get(sub_index).and_then(Word::as_literal) {
            Some("up" | "build") => {
                let global = scan_options(
                    builder,
                    model_node,
                    &ctx.argv[start.saturating_sub(1)..sub_index],
                    start.saturating_sub(1),
                    &FlagSpec {
                        allow_abbreviation: false,
                        value_flags: &[
                            "-f",
                            "--file",
                            "-p",
                            "--project-name",
                            "--project-directory",
                            "--env-file",
                            "--profile",
                            "--parallel",
                            "--progress",
                            "--ansi",
                        ],
                        known_flags: &["--compatibility", "--dry-run"],
                    },
                );
                if !global.unknown_flags.is_empty() {
                    return;
                }
                let mut files: Vec<(u32, Word)> = global
                    .values_of(&["-f", "--file"])
                    .into_iter()
                    .map(|(index, file)| (index, file.clone()))
                    .collect();
                builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
                let mut unresolved_selector = None;
                for (index, file) in global.values_of(&["--env-file"]) {
                    fs_arg_effect(
                        builder,
                        ctx,
                        model_node,
                        index,
                        file,
                        "filesystem.read",
                        ctx.resolve_fs_word(file),
                        Attrs::new(),
                    );
                    if file.as_literal().is_none() {
                        unresolved_selector = Some("--env-file");
                    }
                }
                if files.is_empty() {
                    match ctx.environment_value("COMPOSE_FILE") {
                        Some(ResourceExpr::Literal { value }) if !value.is_empty() => {
                            let separator = ctx.environment_value("COMPOSE_PATH_SEPARATOR");
                            let separator = match &separator {
                                None => Some(":"),
                                Some(ResourceExpr::Literal { value }) if !value.is_empty() => {
                                    Some(value.as_str())
                                }
                                _ => None,
                            };
                            if let Some(separator) = separator {
                                files.extend(
                                    value
                                        .split(separator)
                                        .filter(|p| !p.is_empty())
                                        .map(|path| (sub_index as u32, Word::literal(path))),
                                );
                            } else {
                                unresolved_selector = Some("COMPOSE_PATH_SEPARATOR");
                            }
                        }
                        None | Some(ResourceExpr::Literal { .. }) => {
                            // Env-file contents can select COMPOSE_FILE; do not invent a default.
                            if global.has(&["--env-file"]) {
                                unresolved_selector = Some("--env-file COMPOSE_FILE");
                            }
                        }
                        _ => unresolved_selector = Some("COMPOSE_FILE"),
                    }
                }
                let project_directory = global.value_of(&["--project-directory"]);
                if files.is_empty()
                    && project_directory.is_some_and(|directory| directory.as_literal().is_none())
                {
                    unresolved_selector = Some("--project-directory");
                }
                if files.is_empty() && unresolved_selector.is_none() {
                    let base = project_directory
                        .map(|directory| ctx.resolve_fs_word(directory))
                        .or_else(|| ctx.cwd_resource());
                    fs_arg_effect(
                        builder,
                        ctx,
                        model_node,
                        sub_index as u32,
                        &Word::literal("compose.yaml"),
                        "filesystem.read",
                        ResourceExpr::Union {
                            alternatives: ["compose.yaml", "docker-compose.yml"]
                                .iter()
                                .map(|path| {
                                    crate::paths::resolve_fs_word_with_cwd(
                                        &Word::literal(*path),
                                        base.clone(),
                                    )
                                })
                                .collect(),
                        },
                        Attrs::new(),
                    );
                }
                for (index, file) in files {
                    if file.as_literal().is_none() || file.as_literal() == Some("-") {
                        unresolved_selector = Some("compose file");
                        continue;
                    }
                    fs_arg_effect(
                        builder,
                        ctx,
                        model_node,
                        index,
                        &file,
                        "filesystem.read",
                        ctx.resolve_fs_word(&file),
                        Attrs::new(),
                    );
                }
                if let Some(selector) = unresolved_selector {
                    builder.boundary(Boundary {
                        reason: BoundaryReason::UNRESOLVED_SOURCE,
                        class: BoundaryClass::Unmodeled,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: vec![Domain::new("filesystem")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some(format!("docker compose configuration selector: {selector}")),
                    });
                }
                if global.has(&["--dry-run"]) {
                    return;
                }
                if ctx.argv[sub_index].as_literal() == Some("build") {
                    self.build(builder, ctx, model_node, sub_index + 1, true);
                } else {
                    let parsed = scan_options(
                        builder,
                        model_node,
                        &ctx.argv[sub_index..],
                        sub_index,
                        &FlagSpec {
                            allow_abbreviation: false,
                            value_flags: &[
                                "--pull",
                                "--scale",
                                "--timeout",
                                "-t",
                                "--exit-code-from",
                                "--wait-timeout",
                                "--attach",
                                "--no-attach",
                            ],
                            known_flags: &[
                                "-d",
                                "--detach",
                                "--build",
                                "--no-build",
                                "--no-deps",
                                "--force-recreate",
                                "--no-recreate",
                                "--remove-orphans",
                                "--wait",
                                "--quiet-pull",
                                "--renew-anon-volumes",
                                "-V",
                                "--abort-on-container-exit",
                            ],
                        },
                    );
                    let download =
                        parsed.value_of(&["--pull"]).and_then(Word::as_literal) != Some("never");
                    let services = if parsed.unknown_flags.is_empty() {
                        parsed.operands
                    } else {
                        Vec::new()
                    };
                    let indices: Vec<u32> = if services.is_empty() {
                        vec![sub_index as u32]
                    } else {
                        services.iter().map(|(index, _)| *index).collect()
                    };
                    for index in indices {
                        container_effect(
                            builder,
                            ctx,
                            model_node,
                            index,
                            "container.start",
                            None,
                            Attrs::new(),
                        );
                    }
                    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
                    if download {
                        arg_effect(
                            builder,
                            ctx,
                            model_node,
                            sub_index as u32,
                            "network.download",
                            ResourceExpr::Unresolved {
                                family: ResourceFamily::new("network"),
                            },
                            Attrs::new(),
                        );
                    }
                }
            }
            Some("exec") => self.compose_exec(builder, ctx, model_node, sub_index + 1),
            Some("run") => self.compose_run(builder, ctx, model_node, sub_index + 1),
            Some("down" | "rm") => self.compose_remove(builder, ctx, model_node, sub_index, start),
            verb => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNMODELED_SUBCOMMAND,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(verb.map_or_else(
                        || "docker compose".to_string(),
                        |verb| format!("docker compose {verb}"),
                    )),
                });
            }
        }
    }

    fn image_network(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        verb_index: usize,
        operation: &str,
    ) {
        let spec = if operation == "network.download" {
            FlagSpec {
                allow_abbreviation: false,
                value_flags: &["--platform"],
                known_flags: &[
                    "-a",
                    "--all-tags",
                    "-q",
                    "--quiet",
                    "--disable-content-trust",
                ],
            }
        } else {
            FlagSpec {
                allow_abbreviation: false,
                value_flags: &[
                    "-t",
                    "--tag",
                    "-f",
                    "--file",
                    "--annotation",
                    "--format",
                    "--progress",
                ],
                known_flags: &["--raw", "--append", "--dry-run", "--prefer-index"],
            }
        };
        let parsed = scan_options(
            builder,
            model_node,
            &ctx.argv[verb_index..],
            verb_index,
            &spec,
        );
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        if !parsed.unknown_flags.is_empty() {
            return;
        }
        // A dry run prints the manifest without publishing it.
        if operation == "network.upload" && parsed.has(&["--dry-run"]) {
            return;
        }
        let targets = if operation == "network.upload" {
            parsed.values_of(&["-t", "--tag"])
        } else {
            parsed.operands.clone()
        };
        if targets.is_empty() {
            arg_effect(
                builder,
                ctx,
                model_node,
                verb_index as u32,
                operation,
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new("network"),
                },
                Attrs::new(),
            );
        } else {
            for (index, image) in targets {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    operation,
                    word_resource(image),
                    Attrs::new(),
                );
            }
        }
    }

    fn compose_exec(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
    ) {
        self.exec(builder, ctx, model_node, start, true);
    }

    fn exec(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
        compose: bool,
    ) {
        let RuntimeContext {
            operand_index: i,
            workdir,
            environment,
            environment_sources,
            attributes,
            unknown_flags,
            operand_ambiguous,
            latest,
        } = match runtime_context(ctx.argv, start, compose) {
            Ok(context) => context,
            Err((index, flag)) => {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &DOMAINS,
                    &[(index as u32, flag)],
                );
                return;
            }
        };
        unrecognized_arguments_boundary(builder, model_node, &DOMAINS, &unknown_flags);
        if operand_ambiguous {
            container_effect(
                builder,
                ctx,
                model_node,
                i as u32,
                "container.exec",
                None,
                attributes,
            );
            return;
        }
        let container = (!latest).then(|| ctx.argv.get(i)).flatten();
        if !latest && container.is_none() {
            return;
        }
        container_effect(
            builder,
            ctx,
            model_node,
            i as u32,
            "container.exec",
            container,
            attributes,
        );
        exec_in_container(
            builder,
            ctx,
            model_node,
            i,
            container,
            workdir,
            environment,
            environment_sources,
            latest,
        );
    }

    fn compose_run(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
    ) {
        self.run(builder, ctx, model_node, start, RunMode::Compose);
    }

    fn run(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
        mode: RunMode,
    ) {
        // Volume mounts expose host paths into the container.
        let spec = if mode == RunMode::Compose {
            &DOCKER_COMPOSE_RUN
        } else {
            &DOCKER_RUN
        };
        let (scanned, i, operand_ambiguous) = container_options(ctx.argv, start, spec, false);
        let unknown_flags = scanned.unknown_flags;
        let mut storage = Vec::new();
        let mut storage_provenance = Vec::new();
        let mut name = None;
        let mut workdir = None;
        let mut environment = BTreeMap::new();
        let mut environment_sources = BTreeMap::new();
        let mut entrypoint = None;
        let mut attributes = Attrs::new();
        for flag in scanned.flags {
            if flag.name == "--privileged" {
                attributes.insert("privileged".to_string(), AttrValue::Bool(true));
            }
            let Some(value) = flag.value else {
                if spec.value_flags.contains(&flag.name)
                    && (![
                        "-v",
                        "--volume",
                        "--mount",
                        "--name",
                        "-w",
                        "--workdir",
                        "-e",
                        "--env",
                    ]
                    .contains(&flag.name)
                        || ctx.argv[flag.index as usize].as_literal() != Some(flag.name))
                {
                    unrecognized_arguments_boundary(
                        builder,
                        model_node,
                        &DOMAINS,
                        &[(flag.index, ctx.argv[flag.index as usize].render_raw())],
                    );
                    return;
                }
                match flag.name {
                    "--name" => name = None,
                    "-w" | "--workdir" => workdir = None,
                    _ => {}
                }
                continue;
            };
            let index = flag.value_index.unwrap();
            match flag.name {
                "-v" | "--volume" | "--mount" => {
                    if let Some(mount) = parse_storage_word(&value, ctx.cwd.or(ctx.runtime_cwd)) {
                        if ctx.tracks_host_context_environment() {
                            let node = if matches!(mount, ContainerStorage::BindMount { .. }) {
                                fs_arg_node(builder, ctx, index, &value)
                            } else {
                                arg_node(builder, ctx, index)
                            };
                            storage_provenance.push(node);
                        }
                        if let ContainerStorage::BindMount {
                            host_path,
                            read_only,
                            ..
                        } = &mount
                        {
                            builder
                                .declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
                            fs_arg_effect(
                                builder,
                                ctx,
                                model_node,
                                index,
                                &value,
                                if *read_only {
                                    "filesystem.read"
                                } else {
                                    "filesystem.write"
                                },
                                host_path.clone(),
                                Default::default(),
                            );
                        }
                        storage.push(mount);
                    } else if value.as_literal().is_none()
                        && ctx.argv[flag.index as usize]
                            .literal_prefix()
                            .split('=')
                            .next()
                            == Some(flag.name)
                    {
                        unrecognized_arguments_boundary(
                            builder,
                            model_node,
                            &DOMAINS,
                            &[(index, value.render_raw())],
                        );
                    }
                }
                "--name" => name = value.as_literal().map(|value| (index, value.to_string())),
                "-w" | "--workdir" => workdir = Some((index, value)),
                "-e" | "--env" => {
                    record_environment(&mut environment, &mut environment_sources, &value, index)
                }
                "--entrypoint" => {
                    entrypoint = (value.as_literal() != Some("")).then_some((index as usize, value))
                }
                option => record_container_value_attribute(&mut attributes, option, &value),
            }
        }
        unrecognized_arguments_boundary(builder, model_node, &DOMAINS, &unknown_flags);
        let op = match mode {
            RunMode::Run | RunMode::Compose => "container.run",
            RunMode::Create => "container.create",
        };
        let operand = (!operand_ambiguous).then(|| ctx.argv.get(i)).flatten();
        if operand.is_some() || operand_ambiguous {
            let mut identity_provenance = storage_provenance;
            if mode != RunMode::Compose
                && ctx.tracks_host_context_environment()
                && let Some((index, _)) = &name
            {
                identity_provenance.push(arg_node(builder, ctx, *index));
            }
            run_effect(
                builder,
                ctx,
                model_node,
                i as u32,
                op,
                operand,
                name.as_ref().map(|(_, name)| name.clone()),
                storage.clone(),
                &identity_provenance,
                attributes,
                mode,
            );
        }
        // For `run`, a trailing command overrides the image or service entrypoint and
        // executes inside the container: its effects belong to the container's
        // realm, not the host. The operand identifies that realm.
        if mode != RunMode::Create && operand.is_some() {
            let trailing = &ctx.argv[(i + 1).min(ctx.argv.len())..];
            let command = entrypoint.as_ref().map(|(_, entrypoint)| {
                std::iter::once(entrypoint.clone())
                    .chain(trailing.iter().cloned())
                    .collect::<Vec<_>>()
            });
            let inner = command.as_deref().unwrap_or(trailing);
            if !inner.is_empty() {
                let arg = arg_node(
                    builder,
                    ctx,
                    entrypoint.as_ref().map_or(i + 1, |(index, _)| *index) as u32,
                );
                let runtime = runtime(ctx);
                let realm = effinterp_proto::ExecutionRealm::Container {
                    runtime,
                    name: operand.map(Word::render_raw).unwrap_or_default(),
                };
                let mut argv_provenance = match &entrypoint {
                    Some((index, _)) => ctx.argv_provenance_range(builder, *index..*index + 1),
                    None => Vec::new(),
                };
                argv_provenance.extend(ctx.argv_provenance_range(builder, i + 1..ctx.argv.len()));
                let mut transition_provenance = vec![model_node, arg];
                if ctx.tracks_host_context_environment() {
                    transition_provenance.push(arg_node(builder, ctx, i as u32));
                }
                let environment_nodes = if ctx.tracks_host_context_environment() {
                    {
                        environment_sources
                            .into_iter()
                            .map(|(name, index)| (name, arg_node(builder, ctx, index)))
                            .collect()
                    }
                } else {
                    Default::default()
                };
                let cwd_node = workdir.as_ref().and_then(|(index, _)| {
                    ctx.tracks_host_context_environment()
                        .then(|| arg_node(builder, ctx, *index))
                });
                {
                    let cwd: Option<&Word> = workdir.as_ref().map(|(_, word)| word);
                    {
                        let words: &[Word] = inner;
                        ctx.nest.nest(
                            builder,
                            Transition::exec(
                                words.iter().map(word_resource).collect(),
                                words.to_vec(),
                            )
                            .exec_cwd(cwd.and_then(Word::as_literal))
                            .cwd(
                                cwd.map(|cwd| crate::paths::resolve_fs_word(cwd, None)),
                                cwd_node,
                            )
                            .stdin(ctx.stdin)
                            .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                            .argv_provenance(Some(argv_provenance.as_slice()))
                            .kind(ExecutionEdgeKind::ContainerRealm)
                            .realm(realm)
                            .mounts(storage)
                            .environment(
                                environment,
                                environment_nodes,
                                Default::default(),
                            ),
                            &transition_provenance,
                            ctx.depth,
                        )
                    };
                };
            }
        }
    }

    fn compose_remove(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        verb_index: usize,
        global_start: usize,
    ) {
        let global = scan_options(
            builder,
            model_node,
            &ctx.argv[global_start - 1..verb_index],
            global_start - 1,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &[
                    "-f",
                    "--file",
                    "-p",
                    "--project-name",
                    "--project-directory",
                    "--env-file",
                    "--profile",
                    "--parallel",
                    "--progress",
                    "--ansi",
                ],
                known_flags: &[
                    "--all-resources",
                    "--compatibility",
                    "--dry-run",
                    "--help",
                    "-h",
                    "--version",
                    "-v",
                ],
            },
        );
        let down = ctx.argv[verb_index].as_literal() == Some("down");
        let parsed = scan_options(
            builder,
            model_node,
            &ctx.argv[verb_index..],
            verb_index,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: if down {
                    &["--rmi", "-t", "--timeout"]
                } else {
                    &[]
                },
                known_flags: if down {
                    &[
                        "-v",
                        "--volumes",
                        "--remove-orphans",
                        "--dry-run",
                        "--help",
                        "-h",
                    ]
                } else {
                    &[
                        "-v",
                        "--volumes",
                        "-f",
                        "--force",
                        "-s",
                        "--stop",
                        "--dry-run",
                        "--help",
                        "-h",
                    ]
                },
            },
        );
        if !global.unknown_flags.is_empty() || !parsed.unknown_flags.is_empty() {
            return;
        }
        let mut selected = BTreeMap::new();
        for (root, flag) in global
            .flags
            .iter()
            .map(|flag| (true, flag))
            .chain(parsed.flags.iter().map(|flag| (false, flag)))
            .filter(|(_, flag)| flag.value.is_none())
        {
            let name = match flag.name {
                "-v" if root => "--version",
                "-v" => "--volumes",
                "-f" => "--force",
                "-s" => "--stop",
                "-h" => "--help",
                name => name,
            };
            let enabled = match ctx.argv[flag.index as usize]
                .as_literal()
                .and_then(|text| text.split_once('='))
            {
                None | Some((_, "1" | "t" | "T" | "TRUE" | "true" | "True")) => true,
                Some((_, "0" | "f" | "F" | "FALSE" | "false" | "False")) => false,
                _ => {
                    unrecognized_arguments_boundary(
                        builder,
                        model_node,
                        &DOMAINS,
                        &[(flag.index, ctx.argv[flag.index as usize].render_raw())],
                    );
                    return;
                }
            };
            selected.insert(name, enabled);
        }
        // Compose v2 traverses its root options and runs the named command
        // whatever `--version` says; podman-compose replaces the command with
        // `version`. `podman compose` defers to docker-compose when installed.
        if selected.get("--help") == Some(&true)
            || selected.get("--dry-run") == Some(&true)
            || selected.get("--version") == Some(&true)
                && crate::exec::program_name(&ctx.argv[0]) == Some("podman-compose")
        {
            return;
        }
        let mut attributes = Attrs::from([
            ("runtime".into(), AttrValue::String(runtime(ctx))),
            ("scope".into(), AttrValue::String("compose".into())),
            (
                "mode".into(),
                AttrValue::String(if down { "down" } else { "rm" }.into()),
            ),
            ("active".into(), AttrValue::Bool(true)),
            ("dry_run".into(), AttrValue::Bool(false)),
        ]);
        if let Some(project) = global
            .value_of(&["--project-name", "-p"])
            .and_then(Word::as_literal)
        {
            attributes.insert("project".into(), AttrValue::String(project.into()));
        }
        // No operand means every service, which an empty list would deny.
        if !parsed.operands.is_empty()
            && let Some(services) = complete_list(
                parsed
                    .operands
                    .iter()
                    .map(|(_, service)| service.as_literal().map(|s| AttrValue::String(s.into()))),
            )
        {
            attributes.insert("services".into(), services);
        }
        // Compose service names do not establish runtime container identities.
        if down || selected.get("--stop") == Some(&true) {
            container_effect(
                builder,
                ctx,
                model_node,
                verb_index as u32,
                "container.stop",
                None,
                attributes.clone(),
            );
        }
        if let Some(volumes) = selected.get("--volumes") {
            attributes.insert("volumes".into(), AttrValue::Bool(*volumes));
            attributes.insert("named_volumes".into(), AttrValue::Bool(*volumes && down));
            attributes.insert("anonymous_volumes".into(), AttrValue::Bool(*volumes));
        }
        container_effect(
            builder,
            ctx,
            model_node,
            verb_index as u32,
            "container.remove",
            None,
            attributes,
        );
    }

    fn cp(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
    ) {
        let (i, _) = inner_start(ctx.argv, start, &[], false);
        let operands: Vec<(usize, &Word)> = ctx.argv[i..]
            .iter()
            .enumerate()
            .map(|(off, w)| (i + off, w))
            .filter(|(_, w)| !w.as_literal().is_some_and(|t| t.starts_with('-')))
            .collect();
        // `docker cp SRC DEST`: a `container:path` operand is a container
        // resource, a bare path is on the host (read for src, write for dest).
        if let [(si, src), (di, dest)] = operands.as_slice() {
            let source = cp_side(builder, ctx, model_node, *si as u32, src, "filesystem.read");
            let destination = cp_side(
                builder,
                ctx,
                model_node,
                *di as u32,
                dest,
                "filesystem.write",
            );
            if let (Some(source), Some(destination)) = (source, destination) {
                builder.transfer_binding(TransferBinding::new(source, destination));
            }
        }
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    }

    fn build(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
        compose: bool,
    ) {
        let BuildContext {
            operand_index: i,
            unknown_flags,
            operand_ambiguous,
        } = match build_context(ctx.argv, start) {
            Ok(context) => context,
            Err((index, flag)) => {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &DOMAINS,
                    &[(index as u32, flag)],
                );
                return;
            }
        };
        unrecognized_arguments_boundary(builder, model_node, &DOMAINS, &unknown_flags);
        if compose {
            arg_effect(
                builder,
                ctx,
                model_node,
                start.saturating_sub(1) as u32,
                "filesystem.read",
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new("filesystem"),
                },
                Attrs::new(),
            );
        } else if !operand_ambiguous && let Some(context) = ctx.argv.get(i) {
            operand_effect(
                builder,
                ctx,
                model_node,
                i as u32,
                context,
                "filesystem.read",
                Default::default(),
            );
        }
        builder.declare_coverage(
            Domain::new("filesystem"),
            if operand_ambiguous {
                CoverageLevel::Partial
            } else {
                CoverageLevel::Full
            },
        );
    }

    fn lifecycle(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
        start: usize,
        sub: &str,
    ) {
        let op = match sub {
            "rm" => "container.remove",
            "kill" => "container.kill",
            "stop" => "container.stop",
            "start" => "container.start",
            "restart" => "container.restart",
            "pause" => "container.pause",
            "unpause" => "container.unpause",
            _ => unreachable!(),
        };
        if matches!(sub, "stop" | "kill" | "restart" | "pause") {
            let manager = runtime(ctx);
            let podman = manager == "podman";
            let mut value_flags = Vec::new();
            let mut known_flags = vec!["--help", "-h"];
            if matches!(sub, "stop" | "restart") {
                value_flags.extend(["--time", "-t"]);
                if manager == "docker" {
                    value_flags.push("--timeout");
                }
            }
            if sub == "kill" || !podman && matches!(sub, "stop" | "restart") {
                value_flags.extend(["--signal", "-s"]);
            }
            if podman {
                known_flags.extend(["--all", "-a", "--latest", "-l"]);
                value_flags.push("--cidfile");
                if sub != "kill" {
                    value_flags.extend(["--filter", "-f"]);
                }
                if sub == "stop" {
                    known_flags.extend(["--ignore", "-i"]);
                }
                if sub == "restart" {
                    known_flags.push("--running");
                }
            }
            let parsed = scan_options(
                builder,
                model_node,
                &ctx.argv[start - 1..],
                start - 1,
                &FlagSpec {
                    allow_abbreviation: false,
                    value_flags: &value_flags,
                    known_flags: &known_flags,
                },
            );
            if !parsed.unknown_flags.is_empty() {
                return;
            }
            let mut selected = BTreeMap::new();
            for flag in &parsed.flags {
                if value_flags.contains(&flag.name) {
                    if let Some(value) = flag.value.as_ref().and_then(Word::as_literal)
                        && (matches!(flag.name, "--time" | "--timeout" | "-t")
                            && value.parse::<i64>().is_err()
                            || matches!(flag.name, "--filter" | "-f") && !value.contains('='))
                    {
                        unrecognized_arguments_boundary(
                            builder,
                            model_node,
                            &DOMAINS,
                            &[(flag.index, ctx.argv[flag.index as usize].render_raw())],
                        );
                        return;
                    }
                    continue;
                }
                let enabled = match ctx.argv[flag.index as usize]
                    .as_literal()
                    .map(|text| text.split_once('='))
                {
                    Some(None | Some((_, "1" | "t" | "T" | "TRUE" | "true" | "True"))) => true,
                    Some(Some((_, "0" | "f" | "F" | "FALSE" | "false" | "False"))) => false,
                    _ => {
                        unrecognized_arguments_boundary(
                            builder,
                            model_node,
                            &DOMAINS,
                            &[(flag.index, ctx.argv[flag.index as usize].render_raw())],
                        );
                        return;
                    }
                };
                let name = match flag.name {
                    "-a" => "--all",
                    "-l" => "--latest",
                    "-h" => "--help",
                    "-i" => "--ignore",
                    name => name,
                };
                selected.insert(name, enabled);
            }
            let help = selected.get("--help") == Some(&true);
            let all = selected.get("--all") == Some(&true);
            let latest = selected.get("--latest") == Some(&true);
            let running = selected.get("--running") == Some(&true);
            let filtered = parsed.has(&["--filter", "-f"]);
            let cidfiles = parsed.values_of(&["--cidfile"]);
            let mut attributes = Attrs::from([
                ("all".into(), AttrValue::Bool(all && !filtered)),
                ("active".into(), AttrValue::Bool(!help)),
                ("dry_run".into(), AttrValue::Bool(false)),
            ]);
            let signal = parsed.value_of(&["--signal", "-s"]);
            if let Some(signal) = signal.and_then(Word::as_literal) {
                attributes.insert("signal".into(), AttrValue::String(signal.into()));
            }
            // A kill with its default SIGKILL, or another signal that ends the
            // main process, stops the containers it selects.
            let ops: &[&str] = if sub == "kill"
                && signal.is_none_or(|signal| {
                    signal.as_literal().is_some_and(|signal| {
                        let name = signal.to_ascii_uppercase();
                        matches!(
                            name.strip_prefix("SIG").unwrap_or(&name),
                            "KILL" | "TERM" | "INT" | "QUIT" | "9" | "15" | "2" | "3"
                        )
                    })
                }) {
                &["container.kill", "container.stop"]
            } else {
                &[op]
            };
            // These selectors are exclusive in Podman's CLI. Do not turn an
            // invalid invocation into an operation over the entire manager.
            if !help
                && ((all || filtered) && !parsed.operands.is_empty()
                    || latest && (all || running || filtered || !parsed.operands.is_empty())
                    || !cidfiles.is_empty()
                        && (all || latest || running || filtered || !parsed.operands.is_empty()))
            {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &DOMAINS,
                    &[(start as u32, "conflicting container selectors".into())],
                );
                return;
            }
            if latest || filtered || !cidfiles.is_empty() {
                let selection = if latest {
                    "latest"
                } else if filtered {
                    "filtered"
                } else {
                    "cidfile"
                };
                attributes.insert("selection".into(), AttrValue::String(selection.into()));
                if !help {
                    for (index, file) in cidfiles {
                        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
                        fs_arg_effect(
                            builder,
                            ctx,
                            model_node,
                            index,
                            file,
                            "filesystem.read",
                            ctx.resolve_fs_word(file),
                            Attrs::new(),
                        );
                    }
                    builder.boundary(Boundary {
                        reason: BoundaryReason::UNRESOLVED_SOURCE,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        affected_resource: Some(ResourceExpr::Unresolved {
                            family: ResourceFamily::new("container"),
                        }),
                        callee: None,
                        domains: vec![Domain::new("container")],
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some(format!(
                            "{manager} {sub}: {selection} selects runtime container identities"
                        )),
                    });
                }
                for op in ops {
                    container_effect(
                        builder,
                        ctx,
                        model_node,
                        (start - 1) as u32,
                        op,
                        None,
                        attributes.clone(),
                    );
                }
            } else if all || running {
                if running {
                    attributes.insert("selection".into(), AttrValue::String("running".into()));
                }
                for op in ops {
                    arg_effect(
                        builder,
                        ctx,
                        model_node,
                        (start - 1) as u32,
                        op,
                        ResourceExpr::Pattern {
                            pattern: effinterp_proto::ResourcePattern::Container {
                                runtime: effinterp_proto::Field::Exact {
                                    value: manager.clone(),
                                },
                                name_glob: Some("*".into()),
                                image_glob: None,
                            },
                        },
                        attributes.clone(),
                    );
                }
            } else if help && parsed.operands.is_empty() {
                for op in ops {
                    container_effect(
                        builder,
                        ctx,
                        model_node,
                        (start - 1) as u32,
                        op,
                        None,
                        attributes.clone(),
                    );
                }
            } else {
                for (index, word) in parsed.operands {
                    let mut attributes = attributes.clone();
                    // An opaque operand could select the entire inventory, but
                    // its argument provenance does not establish that selection.
                    if word.as_literal().is_none() {
                        attributes.remove("all");
                    }
                    for op in ops {
                        container_effect(
                            builder,
                            ctx,
                            model_node,
                            index,
                            op,
                            Some(word),
                            attributes.clone(),
                        );
                    }
                }
            }
            return;
        }
        let (i, _) = inner_start(ctx.argv, start, &[], false);
        // `rm --force` kills a running container before removing it, so it
        // stops whatever it removes; a plain `rm` refuses running containers.
        let forced = sub == "rm" && rm_forced(&ctx.argv[start.min(ctx.argv.len())..]);
        for (off, word) in ctx.argv[i..].iter().enumerate() {
            if word.as_literal().is_some_and(|t| t.starts_with('-')) {
                continue;
            }
            if forced {
                container_effect(
                    builder,
                    ctx,
                    model_node,
                    (i + off) as u32,
                    "container.stop",
                    Some(word),
                    Attrs::from([
                        ("active".into(), AttrValue::Bool(true)),
                        ("dry_run".into(), AttrValue::Bool(false)),
                    ]),
                );
            }
            container_effect(
                builder,
                ctx,
                model_node,
                (i + off) as u32,
                op,
                Some(word),
                Default::default(),
            );
        }
    }
}

// Whether `rm`'s options leave force on. Its boolean options are `-f`/`--force`,
// `-l`/`--link` and `-v`/`--volumes`; each takes an optional `=value`, a short
// cluster gives it to its last letter, and the last occurrence wins. Help or
// any other option means rm removes nothing, so it stops nothing either.
fn rm_forced(words: &[Word]) -> bool {
    let mut forced = false;
    for text in words.iter().filter_map(Word::as_literal) {
        if text == "--" {
            break;
        }
        let Some(option) = text.strip_prefix('-') else {
            continue;
        };
        let (names, value) = option
            .split_once('=')
            .map_or((option, None), |(names, value)| (names, Some(value)));
        let value = match value {
            None | Some("1" | "t" | "T" | "TRUE" | "true" | "True") => true,
            Some("0" | "f" | "F" | "FALSE" | "false" | "False") => false,
            Some(_) => return false,
        };
        if let Some(name) = names.strip_prefix('-') {
            match name {
                "force" => forced = value,
                "link" | "volumes" => {}
                _ => return false,
            }
        } else if names.is_empty() || !names.bytes().all(|b| matches!(b, b'f' | b'l' | b'v')) {
            return false;
        } else if let Some(index) = names.rfind('f') {
            forced = value || index + 1 < names.len();
        }
    }
    forced
}

#[allow(clippy::too_many_arguments)]
fn exec_in_container(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    container_index: usize,
    container: Option<&Word>,
    workdir: Option<(u32, Word)>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    environment_sources: BTreeMap<String, u32>,
    latest: bool,
) {
    // The command after the container runs inside it: its effects belong
    // to the container's realm, not the host.
    let inner_start = if latest {
        container_index
    } else {
        container_index + 1
    };
    let inner = &ctx.argv[inner_start.min(ctx.argv.len())..];
    if inner.is_empty() {
        return;
    }
    let arg = arg_node(builder, ctx, inner_start as u32);
    let realm = effinterp_proto::ExecutionRealm::Container {
        runtime: runtime(ctx),
        name: container.map_or_else(|| "?".to_string(), Word::render_raw),
    };
    let argv_provenance = ctx.argv_provenance_range(builder, inner_start..ctx.argv.len());
    let mut transition_provenance = vec![model_node, arg];
    if ctx.tracks_host_context_environment() && !latest {
        transition_provenance.push(arg_node(builder, ctx, container_index as u32));
    }
    let environment_nodes = if ctx.tracks_host_context_environment() {
        {
            environment_sources
                .into_iter()
                .map(|(name, index)| (name, arg_node(builder, ctx, index)))
                .collect()
        }
    } else {
        Default::default()
    };
    let cwd_node = workdir.as_ref().and_then(|(index, _)| {
        ctx.tracks_host_context_environment()
            .then(|| arg_node(builder, ctx, *index))
    });
    {
        let cwd: Option<&Word> = workdir.as_ref().map(|(_, word)| word);
        {
            let words: &[Word] = inner;
            ctx.nest.nest(
                builder,
                Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                    .exec_cwd(cwd.and_then(Word::as_literal))
                    .cwd(
                        cwd.map(|cwd| crate::paths::resolve_fs_word(cwd, None)),
                        cwd_node,
                    )
                    .stdin(ctx.stdin)
                    .runtime_cwd(ctx.nest.current_runtime_cwd().as_deref())
                    .argv_provenance(Some(argv_provenance.as_slice()))
                    .kind(ExecutionEdgeKind::ContainerRealm)
                    .realm(realm)
                    .mounts(Vec::new())
                    .environment(environment, environment_nodes, Default::default()),
                &transition_provenance,
                ctx.depth,
            )
        };
    };
}

fn scan_options<'a>(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    argv: &'a [Word],
    offset: usize,
    spec: &FlagSpec<'a>,
) -> args::Scanned<'a> {
    let mut parsed = args::scan_with_value_indices(argv, spec, true);
    for flag in &mut parsed.flags {
        flag.index += offset as u32;
        flag.value_index = flag.value_index.map(|index| index + offset as u32);
        if spec.value_flags.contains(&flag.name) && flag.value.is_none() {
            parsed
                .unknown_flags
                .push((flag.index - offset as u32, flag.name.to_string()));
        }
    }
    for (index, _) in &mut parsed.operands {
        *index += offset as u32;
    }
    for (index, _) in &mut parsed.unknown_flags {
        *index += offset as u32;
    }
    unrecognized_arguments_boundary(builder, model_node, &DOMAINS, &parsed.unknown_flags);
    parsed
}

fn container_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    word: Option<&Word>,
    attributes: Attrs,
) {
    let resource = match word.and_then(Word::as_literal) {
        Some(name) => ResourceExpr::Concrete {
            identity: ResourceIdentity::Container {
                runtime: runtime(ctx),
                name: Some(name.to_string()),
                image: None,
                storage: Vec::new(),
            },
        },
        None => ResourceExpr::Unresolved {
            family: ResourceFamily::new("container"),
        },
    };
    arg_effect(
        builder, ctx, model_node, index, operation, resource, attributes,
    );
}

fn ps_outputs_all_running(argv: &[Word]) -> bool {
    let (sub_index, _) = inner_start(argv, 1, &ROOT_VALUE_FLAGS, false);
    if argv.get(sub_index).and_then(Word::as_literal) != Some("ps") {
        return false;
    }
    let parsed = scan(
        &argv[sub_index..],
        &FlagSpec {
            allow_abbreviation: false,
            value_flags: &["--filter", "-f"],
            known_flags: &["--quiet", "-q", "--all", "-a"],
        },
    );
    if !parsed.unknown_flags.is_empty() || !parsed.operands.is_empty() {
        return false;
    }
    let quiet = parsed
        .flags
        .iter()
        .any(|flag| matches!(flag.name, "--quiet" | "-q") && flag.value.is_none());
    let all = parsed
        .flags
        .iter()
        .any(|flag| matches!(flag.name, "--all" | "-a"));
    quiet
        && !all
        && parsed
            .flags
            .iter()
            .filter(|flag| matches!(flag.name, "--filter" | "-f"))
            .all(|flag| flag.value.as_ref().and_then(Word::as_literal) == Some("status=running"))
}

/// The operand of `docker run` or `docker compose run`. A compose service
/// names the container because its image is only known from the compose file.
#[allow(clippy::too_many_arguments)]
fn run_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    word: Option<&Word>,
    name: Option<String>,
    storage: Vec<ContainerStorage>,
    identity_provenance: &[ProvenanceRef],
    attributes: Attrs,
    mode: RunMode,
) {
    let resource = match word.and_then(Word::as_literal) {
        Some(operand) => ResourceExpr::Concrete {
            identity: ResourceIdentity::Container {
                runtime: runtime(ctx),
                name: if mode == RunMode::Compose {
                    Some(operand.to_string())
                } else {
                    name
                },
                image: (mode != RunMode::Compose).then(|| operand.to_string()),
                storage,
            },
        },
        None => ResourceExpr::Unresolved {
            family: ResourceFamily::new("container"),
        },
    };
    if identity_provenance.is_empty() {
        arg_effect(
            builder, ctx, model_node, index, operation, resource, attributes,
        );
    } else {
        let mut provenance = vec![arg_node(builder, ctx, index)];
        provenance.extend_from_slice(identity_provenance);
        provenance.push(model_node);
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }
}

/// One side of `docker cp`, returning the endpoint slot the transfer pairing
/// anchors on. A `container:path` operand's endpoint is its `container.copy`
/// interaction with the container resource; the host side's is an ordinary
/// filesystem read or write. Pairing them states the direction across the two
/// realms without inventing an execution inside the container.
fn cp_side(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    word: &Word,
    operation: &str,
) -> Option<u32> {
    if word.as_literal().is_none() {
        unrecognized_arguments_boundary(
            builder,
            model_node,
            &["filesystem", "container"],
            &[(index, word.render_raw())],
        );
    }
    match word.as_literal() {
        // `container:path` — a container-side path, not a host path.
        Some(text) if is_container_path(text) => {
            let name = text.split(':').next().unwrap_or(text).to_string();
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "container.copy",
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container {
                        runtime: runtime(ctx),
                        name: Some(name),
                        image: None,
                        storage: Vec::new(),
                    },
                },
                Default::default(),
            )
        }
        _ => operand_effect(
            builder,
            ctx,
            model_node,
            index,
            word,
            operation,
            Default::default(),
        ),
    }
}

/// A `CONTAINER:path` operand (not a Windows drive or a bare path).
fn is_container_path(text: &str) -> bool {
    match text.split_once(':') {
        Some((name, _)) => name.len() > 1 && !name.contains('/'),
        None => false,
    }
}

fn runtime(ctx: &InvocationCtx<'_>) -> String {
    let runtime =
        effinterp_proto::normalize_container_runtime(ctx.argv[0].as_literal().unwrap_or("docker"));
    runtime
        .strip_suffix("-compose")
        .unwrap_or(&runtime)
        .to_string()
}

fn parse_storage_word(spec: &Word, cwd: Option<&str>) -> Option<ContainerStorage> {
    if let Some(spec) = spec.as_literal() {
        return parse_storage(spec, cwd);
    }
    let (source, target) = split_word_once(spec, ':')?;
    let (target, read_only) =
        split_word_once(&target, ':').map_or((target, false), |(target, options)| {
            let read_only = options.as_literal().is_some_and(mount_is_read_only);
            (target, read_only)
        });
    if source.parts.is_empty() || target.parts.is_empty() {
        return None;
    }
    Some(ContainerStorage::BindMount {
        host_path: resolve_fs_word(&source, cwd),
        container_path: resolve_fs_word(&target, None),
        read_only,
    })
}

pub(super) fn split_word_once(word: &Word, separator: char) -> Option<(Word, Word)> {
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut found = false;
    for part in &word.parts {
        if !found
            && let WordPart::Literal(text) = part
            && let Some((left, right)) = text.split_once(separator)
        {
            if !left.is_empty() {
                before.push(WordPart::Literal(left.to_string()));
            }
            if !right.is_empty() {
                after.push(WordPart::Literal(right.to_string()));
            }
            found = true;
        } else if found {
            after.push(part.clone());
        } else {
            before.push(part.clone());
        }
    }
    found.then(|| (Word::new(before), Word::new(after)))
}

/// Host path from a `-v host:container[:opts]` mount spec, when the source is
/// a path rather than a named volume.
fn parse_storage(spec: &str, cwd: Option<&str>) -> Option<ContainerStorage> {
    if spec.contains("source=") || spec.contains("src=") {
        let value = |names: &[&str]| {
            spec.split(',').find_map(|field| {
                let (key, value) = field.split_once('=')?;
                (names.contains(&key) && !value.is_empty()).then(|| value.to_string())
            })
        };
        let source = value(&["source", "src"])?;
        let target = value(&["target", "dst", "destination"])?;
        let read_only = spec.split(',').any(mount_is_read_only);
        let container_path = crate::paths::resolve_fs_path(&target, None);
        if value(&["type"]).as_deref() == Some("volume") {
            return Some(ContainerStorage::Volume {
                name: source,
                container_path,
            });
        }
        return Some(ContainerStorage::BindMount {
            host_path: crate::paths::resolve_fs_path(&source, cwd),
            container_path,
            read_only,
        });
    }
    let mut fields = spec.split(':');
    let source = fields.next()?.to_string();
    let target = fields.next()?.to_string();
    if source.is_empty() || target.is_empty() {
        return None;
    }
    let container_path = crate::paths::resolve_fs_path(&target, None);
    let read_only = fields.any(mount_is_read_only);
    if source.starts_with('/') || source.starts_with('.') || source.starts_with('~') {
        Some(ContainerStorage::BindMount {
            host_path: crate::paths::resolve_fs_path(&source, cwd),
            container_path,
            read_only,
        })
    } else {
        Some(ContainerStorage::Volume {
            name: source,
            container_path,
        })
    }
}

fn mount_is_read_only(option: &str) -> bool {
    option.split(',').any(|option| {
        let (name, value) = option.split_once('=').unwrap_or((option, "true"));
        matches!(name, "ro" | "readonly") && value == "true"
    })
}

struct RuntimeContext {
    operand_index: usize,
    workdir: Option<(u32, Word)>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    environment_sources: BTreeMap<String, u32>,
    attributes: Attrs,
    unknown_flags: Vec<(u32, String)>,
    operand_ambiguous: bool,
    latest: bool,
}

fn runtime_context(
    argv: &[Word],
    start: usize,
    compose: bool,
) -> Result<RuntimeContext, (usize, String)> {
    let spec = if compose {
        &DOCKER_COMPOSE_EXEC
    } else {
        &DOCKER_EXEC
    };
    let (scanned, operand_index, operand_ambiguous) = container_options(argv, start, spec, true);
    let mut context = RuntimeContext {
        operand_index,
        workdir: None,
        environment: BTreeMap::new(),
        environment_sources: BTreeMap::new(),
        attributes: Attrs::new(),
        unknown_flags: scanned.unknown_flags,
        operand_ambiguous,
        latest: false,
    };
    for flag in scanned.flags {
        match flag.name {
            "--privileged" => {
                context
                    .attributes
                    .insert("privileged".into(), AttrValue::Bool(true));
            }
            "-l" | "--latest" if !compose => context.latest = true,
            _ => {}
        }
        let Some(value) = flag.value else {
            if spec.value_flags.contains(&flag.name) {
                return Err((flag.index as usize, argv[flag.index as usize].render_raw()));
            }
            continue;
        };
        let index = flag.value_index.unwrap();
        match flag.name {
            "-w" | "--workdir" => context.workdir = Some((index, value)),
            "-e" | "--env" => record_environment(
                &mut context.environment,
                &mut context.environment_sources,
                &value,
                index,
            ),
            _ => {}
        }
    }
    Ok(context)
}

struct BuildContext {
    operand_index: usize,
    unknown_flags: Vec<(u32, String)>,
    operand_ambiguous: bool,
}

fn build_context(argv: &[Word], start: usize) -> Result<BuildContext, (usize, String)> {
    let (scanned, operand_index, operand_ambiguous) =
        container_options(argv, start, &DOCKER_BUILD, true);
    if let Some(flag) = scanned
        .flags
        .iter()
        .find(|flag| DOCKER_BUILD.value_flags.contains(&flag.name) && flag.value.is_none())
    {
        return Err((flag.index as usize, argv[flag.index as usize].render_raw()));
    }
    Ok(BuildContext {
        operand_index,
        operand_ambiguous,
        unknown_flags: scanned.unknown_flags,
    })
}

/// Keep Docker's unknown-option arity decision separate from argument tokenization.
fn container_options<'a>(
    argv: &'a [Word],
    start: usize,
    spec: &FlagSpec<'static>,
    dash_is_option: bool,
) -> (Scanned<'a>, usize, bool) {
    let offset = start - 1;
    let mut scanned = scan(&argv[offset..], spec);
    for flag in &mut scanned.flags {
        flag.index += offset as u32;
        flag.value_index = flag.value_index.map(|index| index + offset as u32);
        if flag.value_index == Some(flag.index)
            && !flag.name.starts_with("--")
            && argv[flag.index as usize]
                .literal_prefix()
                .starts_with(&format!("{}=", flag.name))
        {
            flag.value = Some(strip_literal_prefix(
                &argv[flag.index as usize],
                flag.name.len() + 1,
            ));
        }
    }
    for (index, _) in &mut scanned.operands {
        *index += offset as u32;
    }
    for (index, name) in &mut scanned.unknown_flags {
        *index += offset as u32;
        *name = argv[*index as usize].render_raw();
    }
    // Preserve the model's supported spellings: short values use '=' or a
    // separate word, and boolean options with '=' remain explicit gaps.
    for flag in &scanned.flags {
        let word = &argv[flag.index as usize];
        let unsupported = flag.value_index == Some(flag.index)
            && !flag.name.starts_with("--")
            && !word
                .literal_prefix()
                .starts_with(&format!("{}=", flag.name))
            || flag.value.is_none() && word.split_assignment().is_some()
            || flag.name == "-l" && flag.value.is_none() && word.as_literal() != Some("-l");
        if unsupported {
            scanned.unknown_flags.push((flag.index, word.render_raw()));
        }
    }
    // A bare dash is an unsupported option here, not a container or build context.
    for (index, word) in &scanned.operands {
        if dash_is_option
            && word.as_literal() == Some("-")
            && scanned
                .dashdash
                .is_none_or(|dd| *index < dd + offset as u32)
        {
            scanned.unknown_flags.push((*index, "-".into()));
        }
    }
    scanned.operands.retain(|(index, word)| {
        !dash_is_option
            || word.as_literal() != Some("-")
            || scanned
                .dashdash
                .is_some_and(|dd| *index > dd + offset as u32)
    });
    let symbolic_operands = scanned
        .flags
        .iter()
        .map(|flag| flag.index)
        .chain(scanned.unknown_flags.iter().map(|(index, _)| *index))
        .filter(|index| {
            argv[*index as usize].as_literal().is_none()
                && argv[*index as usize].split_assignment().is_none()
        })
        .collect::<Vec<_>>();
    for index in &symbolic_operands {
        scanned.operands.push((*index, &argv[*index as usize]));
    }
    scanned.operands.sort_by_key(|(index, _)| *index);
    scanned.operands.dedup_by_key(|(index, _)| *index);
    scanned
        .unknown_flags
        .retain(|(index, _)| !symbolic_operands.contains(index));
    scanned.unknown_flags.sort_by_key(|(index, _)| *index);
    scanned.unknown_flags.dedup_by_key(|(index, _)| *index);
    scanned.flags.retain(|flag| {
        !symbolic_operands.contains(&flag.index)
            && !scanned
                .unknown_flags
                .iter()
                .any(|(index, _)| *index == flag.index)
    });
    scanned.dashdash = scanned.dashdash.map(|index| index + offset as u32);
    let mut end = scanned
        .operands
        .first()
        .map_or(argv.len(), |(index, _)| *index as usize);
    if let Some(separator) = scanned.dashdash {
        end = end.min(separator as usize + 1);
    }
    let ambiguous = scanned
        .unknown_flags
        .iter()
        .find(|(index, _)| {
            (*index as usize) < end
                && !argv[*index as usize].literal_prefix().contains('=')
                && unknown_option_arity_ambiguous(argv, *index as usize)
        })
        .map(|(index, _)| *index as usize);
    if let Some(index) = ambiguous {
        end = index;
    }
    scanned.flags.retain(|flag| (flag.index as usize) < end);
    scanned
        .unknown_flags
        .retain(|(index, _)| (*index as usize) < end || ambiguous == Some(*index as usize));
    (scanned, end, ambiguous.is_some())
}

fn record_environment(
    environment: &mut BTreeMap<String, Option<ResourceExpr>>,
    environment_sources: &mut BTreeMap<String, u32>,
    word: &Word,
    index: u32,
) {
    match word.split_assignment() {
        Some((name, value)) if !name.is_empty() => {
            environment.insert(name.to_string(), Some(word_resource(&value)));
            environment_sources.insert(name.to_string(), index);
        }
        None if word.as_literal().is_some_and(|value| !value.is_empty()) => {
            let value = word.as_literal().unwrap();
            environment.insert(
                value.to_string(),
                Some(ResourceExpr::Environment {
                    name: value.to_string(),
                }),
            );
            environment_sources.insert(value.to_string(), index);
        }
        _ => {}
    }
}

fn record_container_value_attribute(attributes: &mut Attrs, option: &str, value: &Word) {
    let Some(value) = value.as_literal() else {
        return;
    };
    let key = match option {
        "--pid" if value == "host" => "pid",
        "--network" | "--net" if value == "host" => "network",
        "--ipc" if value == "host" => "ipc",
        "--userns" if value == "host" => "userns",
        "--uts" if value == "host" => "uts",
        "--cap-add" => "cap_add",
        "--device" => "device",
        "--security-opt" => "security_opt",
        _ => return,
    };
    let mut values: Vec<String> = attributes
        .get(key)
        .and_then(|value| match value {
            AttrValue::String(value) => Some(value.split(',').map(str::to_string).collect()),
            _ => None,
        })
        .unwrap_or_default();
    values.extend(value.split(',').map(str::to_string));
    values.sort();
    values.dedup();
    attributes.insert(key.to_string(), AttrValue::String(values.join(",")));
}

fn unknown_option_arity_ambiguous(argv: &[Word], index: usize) -> bool {
    argv[index].split_assignment().is_none()
        && argv
            .get(index + 1)
            .is_some_and(|word| !word.render_raw().starts_with('-'))
}
fn daemon_transport(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model: ProvenanceRef,
    end: usize,
) {
    // Only global options select this daemon; a nested command owns its own argv.
    let global = InvocationCtx {
        argv: &ctx.argv[..end],
        cwd_resource: ctx.cwd_resource.clone(),
        model_stack: ctx.model_stack.clone(),
        ..*ctx
    };
    let mut provenance = vec![model];
    let endpoint = crate::models::scope::scope_option(
        builder,
        &global,
        &mut provenance,
        &["-H", "--host", "--url"],
        true,
        "network",
    );
    let context = crate::models::scope::scope_option(
        builder,
        &global,
        &mut provenance,
        &["-c", "--context", "--connection"],
        true,
        "network",
    );
    let endpoint = if context.is_some() {
        None
    } else {
        endpoint.or_else(|| {
            let name = if runtime(ctx) == "podman" {
                "CONTAINER_HOST"
            } else {
                "DOCKER_HOST"
            };
            let value = ctx.environment_value(name)?;
            if let Some(node) = ctx.nest.current_environment_node(name) {
                provenance.push(node);
            } else if ctx.tracks_host_context_environment() {
                provenance.push(builder.node(
                    effinterp_proto::ProvenanceKind::HostContext {
                        name: format!("env.{name}"),
                    },
                    &[],
                ));
            }
            Some(effinterp_proto::ScopeValue::value(value))
        })
    };
    if let Some(effinterp_proto::ScopeValue::Value(value)) = endpoint {
        let prefix = match value.as_ref() {
            ResourceExpr::Literal { value } => Some(value.as_str()),
            ResourceExpr::Join { parts } => parts.first().and_then(|part| match part {
                ResourceExpr::Literal { value } => Some(value.as_str()),
                _ => None,
            }),
            _ => None,
        };
        if let Some(prefix) = prefix {
            if prefix.starts_with("unix://") || prefix.starts_with("npipe://") {
                return;
            }
            if ["tcp://", "http://", "https://", "ssh://"]
                .iter()
                .any(|scheme| prefix.starts_with(scheme))
            {
                let mut scope = effinterp_proto::ResourceScope::new(
                    effinterp_proto::NamespaceKind::Unsupported,
                );
                crate::models::scope::endpoint_evidence(
                    &mut scope,
                    effinterp_proto::ScopeEvidenceKind::Endpoint,
                    effinterp_proto::ScopeValue::Value(value),
                );
                super::infrastructure::emit(
                    builder,
                    &provenance,
                    "network.connect",
                    crate::models::scope::network_resource(&scope),
                );
                return;
            }
        }
    }
    super::infrastructure::environment_gap(
        builder,
        &provenance,
        &["network"],
        BoundaryReason::DAEMON_TRANSPORT,
        "container daemon transport is not established",
    );
}
