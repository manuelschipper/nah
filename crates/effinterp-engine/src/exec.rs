use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Condition, CoverageLevel, Domain,
    Effect, ExecutionEdgeKind, ExecutionInputReason, ExecutionInputRole, ExecutionPhase,
    ExecutionSelector, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, Subject,
};

use crate::SourcePurpose;
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::models::common::{
    RuntimeSourceLanguage, RuntimeSourceOutcome, arg_node, code_execution, operand_effect,
    runtime_searched_source, runtime_selected_source, runtime_unobserved_input,
    shell_launch_arguments,
};
use crate::models::{InvocationCtx, StdinValue, model_application_node, source_refusal_detail};
use crate::nest::{Nest, SourceResolution, Transition, word_resource};
use crate::paths::process_identity_with_cwd;
use crate::value::{SemanticValue, SemanticValueKind, unresolved_resource};
use crate::word::{Word, WordPart};

pub(crate) enum UnresolvedHead {
    /// Nothing after an unresolved command head is analyzed.
    Opaque,
    /// The words after an unresolved shell head are a likely command.
    LikelyWrapper { condition: Condition },
}

/// A model chosen from a basename does not establish that an executable at an
/// arbitrary path is the multiplexer that basename names. A bare command word
/// is resolved through `PATH`, and the system program directories hold the
/// installed tool; anything else is a file whose identity is unestablished.
pub(crate) fn established_program(argv0: &Word) -> bool {
    let Some(text) = argv0.as_literal() else {
        return false;
    };
    if !text.contains('/') {
        return true;
    }
    matches!(
        std::path::Path::new(text)
            .parent()
            .and_then(std::path::Path::to_str),
        Some("/bin" | "/sbin" | "/usr/bin" | "/usr/sbin")
    )
}

/// Text a carrier hands to another terminal: a submitted line runs there, while
/// typed text waits in the receiver's line editor until someone submits it.
enum TerminalText {
    Submitted(String),
    Typed(String),
}

/// The command name a model dispatches on: an established program's basename,
/// or else the literal path, which names no modeled tool.
pub(crate) fn program_name(argv0: &Word) -> Option<&str> {
    let text = argv0.as_literal()?;
    if !established_program(argv0) {
        return Some(text);
    }
    text.rsplit('/').next()
}

/// Enter a literal command delivered to another terminal. The receiver's cwd
/// and environment belong to that terminal, while the command text itself is
/// exact evidence supplied by the carrier invocation.
fn terminal_carrier(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    command: &str,
    arg0: ProvenanceRef,
) -> bool {
    if !ctx.argv.first().is_some_and(established_program) {
        return false;
    }
    let payload = match command {
        "herdr" => herdr_terminal_payload(ctx),
        "tmux" => tmux_terminal_payload(ctx),
        _ => return false,
    };
    let Some((start, text)) = payload else {
        return false;
    };
    let model_node = builder.node(
        ProvenanceKind::ModelApplication {
            model: "terminal/carrier@v0".to_string(),
        },
        &[arg0],
    );
    match text {
        TerminalText::Submitted(source) => terminal_delivery(
            builder, ctx, model_node, arg0, command, start, source, false,
        ),
        TerminalText::Typed(text) => {
            terminal_input(builder, ctx, model_node, arg0, command, start, text)
        }
    }
    true
}

/// Type literal text into another terminal without submitting it. Nothing
/// runs until someone presses Enter there, so the programs the text names are
/// candidates, not launches. The text is analyzed as the receiver's shell
/// would read it only to find those programs, and that analysis is discarded;
/// each candidate is stated as code handed to the terminal, carrying the text.
fn terminal_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    arg0: ProvenanceRef,
    command: &str,
    start: usize,
    text: String,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    let mut provenance = vec![model_node];
    provenance.extend((start..ctx.argv.len()).map(|index| arg_node(builder, ctx, index as u32)));
    let checkpoint = builder.checkpoint();
    let first_effect = builder.effects_len();
    ctx.nest.nest(
        builder,
        Transition::file(Subject::Shell {
            source: text.clone(),
            cwd: None,
            context: Default::default(),
        })
        .kind(ExecutionEdgeKind::ToolModel)
        .source_cwd(None)
        .runtime_cwd(None)
        .cwd(
            Some(ResourceExpr::Parameter {
                name: "terminal_cwd".to_string(),
            }),
            None,
        )
        .inherit_environment(false),
        &provenance,
        ctx.depth,
    );
    let mut candidates = Vec::new();
    for index in first_effect..builder.effects_len() {
        if builder.effect_operation(index) == Some("process.exec")
            && let Some(resource @ ResourceExpr::Concrete { .. }) = builder.effect_resource(index)
            && !candidates.contains(resource)
        {
            candidates.push(resource.clone());
        }
    }
    builder.rollback(checkpoint);
    if candidates.is_empty() {
        candidates.push(unresolved_resource("process"));
    }
    for resource in candidates {
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new("process.code_execution"),
            resource,
            attributes: [("source", "terminal_input"), ("text", text.as_str())]
                .into_iter()
                .map(|(name, value)| {
                    (
                        name.to_string(),
                        effinterp_proto::AttrValue::String(value.to_string()),
                    )
                })
                .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: provenance.clone(),
        });
    }
    unmodeled(
        builder,
        arg0,
        &format!(
            "no model for command {command:?}: the literal text is typed into the receiver terminal, but whether that terminal submits it is not statically recoverable"
        ),
    );
}

/// Hand a literal command line to a terminal session this invocation does not
/// own. The text is exact, but the session's working directory is the
/// receiver's, so nothing in the payload resolves against this caller's.
/// `inherit_environment` separates the two deliveries: a session created here
/// starts from this process's environment, while one selected at runtime
/// carries whatever its own session holds.
#[allow(clippy::too_many_arguments)]
pub(crate) fn terminal_delivery(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    arg0: ProvenanceRef,
    command: &str,
    start: usize,
    source: String,
    inherit_environment: bool,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    code_execution(
        effinterp_proto::RequestAssurance::Exact,
        builder,
        ctx,
        model_node,
        Some(start as u32),
        "argument",
        Default::default(),
    );
    let mut provenance = vec![model_node];
    provenance.extend((start..ctx.argv.len()).map(|index| arg_node(builder, ctx, index as u32)));
    let first_effect = builder.effects_len();
    ctx.nest.nest(
        builder,
        Transition::file(Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .kind(ExecutionEdgeKind::ToolModel)
        .source_cwd(None)
        .runtime_cwd(None)
        .cwd(
            Some(ResourceExpr::Parameter {
                name: "terminal_cwd".to_string(),
            }),
            None,
        )
        .inherit_environment(inherit_environment),
        &provenance,
        ctx.depth,
    );
    if let Some(effect) = (first_effect..builder.effects_len())
        .find(|index| builder.effect_operation(*index) == Some("process.exec"))
    {
        builder.set_effect_string_attribute(effect, "delivery", "terminal");
    }
    unmodeled(
        builder,
        arg0,
        &format!(
            "no model for command {command:?}: the literal command is delivered, but the receiver terminal state is not statically recoverable"
        ),
    );
}

fn literal_join(argv: &[Word], start: usize, end: usize) -> Option<String> {
    Some(
        argv.get(start..end)?
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()?
            .join(" "),
    )
}

/// `herdr [--session S] pane run|send-text|send-keys <pane> …`: `run` submits
/// its words as one line, `send-text` types its one text operand, and
/// `send-keys` types keys that a final Enter submits.
fn herdr_terminal_payload(ctx: &InvocationCtx<'_>) -> Option<(usize, TerminalText)> {
    let mut index = 1;
    if ctx.argv.get(index)?.as_literal()? == "--session" {
        ctx.argv.get(index + 1)?.as_literal()?;
        index += 2;
    }
    if ctx.argv.get(index)?.as_literal()? != "pane" {
        return None;
    }
    let action = ctx.argv.get(index + 1)?.as_literal()?;
    ctx.argv
        .get(index + 2)?
        .as_literal()
        .filter(|target| !target.starts_with('-'))?;
    let start = index + 3;
    let text = match action {
        "run" => literal_join(ctx.argv, start, ctx.argv.len())
            .filter(|payload| !payload.is_empty())
            .map(TerminalText::Submitted)?,
        "send-text" if ctx.argv.len() == start + 1 => ctx.argv[start]
            .as_literal()
            .filter(|text| !text.is_empty())
            .map(|text| TerminalText::Typed(text.to_string()))?,
        "send-keys" => terminal_keys(&ctx.argv[start..], false)?,
        _ => return None,
    };
    Some((start, text))
}

/// Keys sent to a terminal. A key that names no special key is typed as its
/// literal text, and a final Enter (also spelled `enter`, `Return` or `C-m`)
/// submits the line. Any other named key edits the line in a way this
/// analysis does not replay. `literal` sends every key as text.
fn terminal_keys(keys: &[Word], literal: bool) -> Option<TerminalText> {
    let keys = keys
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    let (submit, typed) = match keys.split_last()? {
        (last, rest) if !literal && matches!(*last, "Enter" | "enter" | "Return" | "C-m") => {
            (true, rest)
        }
        _ => (false, keys.as_slice()),
    };
    if !literal
        && typed.iter().any(|key| {
            key.starts_with("C-")
                || key.starts_with("M-")
                || key.starts_with("ctrl+")
                || matches!(
                    *key,
                    "Enter"
                        | "enter"
                        | "Return"
                        | "Escape"
                        | "esc"
                        | "BSpace"
                        | "Tab"
                        | "Space"
                        | "Up"
                        | "Down"
                        | "Left"
                        | "Right"
                )
        })
    {
        return None;
    }
    let text = typed.concat();
    if text.is_empty() {
        return None;
    }
    Some(if submit {
        TerminalText::Submitted(text)
    } else {
        TerminalText::Typed(text)
    })
}

fn tmux_terminal_payload(ctx: &InvocationCtx<'_>) -> Option<(usize, TerminalText)> {
    let mut index = tmux_operand(ctx.argv, 1, "fLSTc", "2CDlNquvV")?;
    let subcommand = ctx.argv.get(index)?.as_literal()?;
    index += 1;
    match subcommand {
        "send-keys" | "send" => {
            let start = tmux_operand(ctx.argv, index, "cNt", "FHKlMRX")?;
            let literal = ctx.argv.get(index..start)?.iter().any(|word| {
                word.as_literal()
                    .is_some_and(|word| word.starts_with('-') && word.contains('l'))
            });
            Some((start, terminal_keys(&ctx.argv[start..], literal)?))
        }
        "new-window" | "neww" => {
            let start = tmux_operand(ctx.argv, index, "ceFnt", "abdkPS")?;
            let source = literal_join(ctx.argv, start, ctx.argv.len())?;
            (!source.is_empty()).then_some((start, TerminalText::Submitted(source)))
        }
        _ => None,
    }
}

fn tmux_operand(argv: &[Word], mut index: usize, values: &str, booleans: &str) -> Option<usize> {
    while let Some(word) = argv.get(index) {
        let text = word.as_literal()?;
        if text == "--" {
            return Some(index + 1);
        }
        if !text.starts_with('-') || text == "-" {
            return Some(index);
        }
        let mut characters = text[1..].chars();
        while let Some(character) = characters.next() {
            if booleans.contains(character) {
                continue;
            }
            if !values.contains(character) {
                return None;
            }
            if characters.as_str().is_empty() {
                index += 1;
                argv.get(index)?.as_literal()?;
            }
            break;
        }
        index += 1;
    }
    Some(index)
}

/// Analyze one argv invocation into the builder. `scope` is the provenance
/// node of the nested invocation that produced this argv, or None at the
/// top level; `depth` bounds further nesting the invocation's model spawns.
#[allow(clippy::too_many_arguments)]
pub(crate) fn analyze_exec(
    builder: &mut PlanBuilder,
    nest: &Nest,
    argv: &[Word],
    stdin: Option<&StdinValue>,
    unresolved_head: UnresolvedHead,
    argv_union_groups: Option<&[Option<ProvenanceRef>]>,
    argv_provenance: Option<&[Vec<ProvenanceRef>]>,
    cwd: Option<&str>,
    runtime_cwd: Option<&str>,
    command_search_path: Option<ResourceExpr>,
    scope: Option<ProvenanceRef>,
    cwd_node: Option<ProvenanceRef>,
    depth: u64,
) -> bool {
    let cwd_resource = scope
        .and_then(|_| builder.current_execution_cwd())
        .or_else(|| {
            cwd.map(|cwd| ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath {
                    path: crate::paths::normalize_cwd(cwd),
                },
            })
        })
        .or_else(|| builder.current_execution_cwd());
    let mut ctx = InvocationCtx {
        argv,
        stdin,
        argv_provenance,
        cwd,
        cwd_resource: cwd_resource.clone(),
        runtime_cwd,
        scope,
        cwd_node,
        nest,
        depth,
        model_stack: Vec::new(),
    };
    let arg0 = builder.node(
        ProvenanceKind::Argument { index: 0 },
        &ctx.arg_antecedents(0),
    );

    // A symbolic directory does not hide a literal executable basename.
    // Keep the original path expression in the execution input; Process.path
    // can only represent a concrete path. Empty basenames remain unresolved.
    let has_cwd_resource = cwd_resource.is_some();
    let literal_basename = match argv[0].parts.last() {
        Some(WordPart::Literal(tail)) => tail.rsplit_once('/').map(|(_, name)| name),
        _ => None,
    }
    .filter(|name| !name.is_empty());
    let process = argv[0].as_literal().or(literal_basename).map(|_| {
        let mut process = SemanticValue::from(ResourceExpr::Concrete {
            identity: process_identity_with_cwd(argv, cwd_resource),
        });
        if let Some(name) = literal_basename
            && let SemanticValueKind::Process { executable, .. } = &mut process.kind
        {
            *executable = name.to_string();
        }
        if !has_cwd_resource
            && runtime_cwd.is_none()
            && let SemanticValueKind::Process { cwd, .. } = &mut process.kind
        {
            *cwd = Some(Box::new(SemanticValue::parameter("cwd")));
        }
        process
    });
    let name = match process.as_ref().map(|value| &value.kind) {
        Some(SemanticValueKind::Process { executable, .. }) if !executable.is_empty() => {
            executable.clone()
        }
        _ => {
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("process.exec"),
                resource: unresolved_resource("process"),
                attributes: Default::default(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![arg0],
            });
            if let UnresolvedHead::LikelyWrapper { condition } = unresolved_head
                && let Some(tail) = argv.get(1).and_then(Word::as_literal)
                && !tail.is_empty()
                && !tail.starts_with('-')
                // These verbs commonly select a subcommand of the unknown head.
                && !matches!(tail, "init" | "install" | "update" | "build" | "run"
                    | "start" | "stop" | "restart" | "status" | "help" | "test")
                && let Some(name) = tail.rsplit('/').next().filter(|name| !name.is_empty())
                && nest.catalog.find(name).is_some()
            {
                command_boundary(
                    builder,
                    arg0,
                    BoundaryReason::UNRESOLVED_COMMAND,
                    BoundaryClass::Unresolved,
                    &["process"],
                    "executable name is not statically resolvable; the words after it were analyzed as the likely command",
                );
                builder.push_condition(condition);
                {
                    let words: &[Word] = &argv[1..];
                    nest.nest(
                        builder,
                        Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                            .exec_cwd(cwd)
                            .cwd(
                                builder.current_execution_cwd(),
                                (nest.current_runtime_cwd().as_deref() == cwd)
                                    .then(|| nest.current_cwd_node())
                                    .flatten(),
                            )
                            .stdin(ctx.stdin)
                            .runtime_cwd(nest.current_runtime_cwd().as_deref()),
                        &[arg0],
                        depth,
                    )
                };
                builder.pop_condition();
                return false;
            }
            unresolved(
                builder,
                arg0,
                "executable name is not statically resolvable",
            );
            return false;
        }
    };
    // A bare name selects its program the way the platform the command runs
    // on resolves executables.
    let cwd_path = match &ctx.cwd_resource {
        Some(ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        }) => Some(path.as_str()),
        _ => None,
    };
    let bare = argv[0].as_literal() == Some(name.as_str());
    let mut platform_name = bare
        .then(|| crate::models::program_name(&name, cwd_path).into_owned())
        .filter(|platform_name| *platform_name != name);
    // A Windows host runs `node.exe` as node from any cwd, including a POSIX
    // shell's. A Linux host may be WSL, whose interop runs a Windows `.exe`
    // found on PATH; elsewhere on Linux the name is an unrelated file, whose
    // behavior stays a boundary. macOS runs no Windows executables.
    let dialect = ctx.os_dialect(builder);
    if platform_name.is_none()
        && bare
        && dialect != effinterp_proto::OsDialect::Macos
        && let Some(stem) = crate::models::exe_stem(&name)
    {
        if dialect != effinterp_proto::OsDialect::Windows {
            unmodeled(
                builder,
                arg0,
                &format!("no model for command {name:?} outside WSL interop"),
            );
        }
        platform_name = Some(stem);
    }
    let renamed = platform_name.is_some();
    let name = platform_name.unwrap_or(name);
    let mut process = process.unwrap();
    let PathSelection {
        outcome: path_outcome,
        certified,
    } = select_path_executable(builder, &ctx, arg0, command_search_path);
    // PATH selection is additional evidence for a slash-free argv[0]. An
    // observed search must establish the selected executable before a
    // basename model can be used; otherwise a same-named model could certify
    // the wrong file. Ambient PATH absence keeps the historical catalog
    // lookup. Absolute-path executables ignore PATH. A search certified by
    // host observation names the executable's path.
    if let Some((selected, _)) = &certified
        && let SemanticValueKind::Process { path, .. } = &mut process.kind
    {
        *path = Some(selected.clone());
    }
    native_loader_inputs(builder, &ctx, arg0);
    // A case-folded or `.exe` spelling runs the catalog program: it selects the
    // model and its interpretation, but never the host identity or evidence,
    // which the original argv above established from the real executable.
    let dispatch_name = crate::models::folded_program(&name).unwrap_or_else(|| name.clone());
    if dispatch_name == "bun" {
        crate::models::nodeexec::bun_runtime_inputs(builder, &ctx, arg0);
    } else if dispatch_name == "deno" {
        crate::models::nodeexec::deno_runtime_inputs(builder, &ctx, arg0);
    } else if dispatch_name == "composer"
        && ctx
            .argv
            .get(1)
            .and_then(Word::as_literal)
            .is_some_and(|subcommand| matches!(subcommand, "install" | "update"))
        && !ctx
            .argv
            .iter()
            .filter_map(Word::as_literal)
            .any(|option| option == "--no-plugins")
    {
        crate::models::pkgmgr::composer_plugin_inputs(builder, &ctx, arg0);
    }
    // A prior mutation of the selected path invalidates a model identified
    // only by its basename. Resolve the written program or retain its boundary.
    let written_executable = argv[0]
        .as_literal()
        .filter(|path| path.contains('/'))
        .is_some_and(|_| builder.executable_was_written(&ctx.resolve_fs_word(&argv[0])));
    // A PATH search that ends in a boundary leaves the executable's identity
    // unestablished, not refuted: the spelled program most likely runs. A
    // model that opts in still applies, with every effect it states
    // conditional on that identity, beside the search's own boundary.
    let unresolved_identity = path_outcome == Some(RuntimeSourceOutcome::Boundary);
    let model = (!written_executable)
        .then(|| nest.catalog.find(&name))
        .flatten()
        .filter(|model| {
            path_outcome.is_none()
                || (unresolved_identity && model.applies_under_unresolved_identity(&ctx))
        });
    if model.is_none_or(|model| model.records_process()) {
        let mut provenance = if ctx.argv_provenance.is_some() {
            argv.iter()
                .enumerate()
                .map(|(index, _)| {
                    builder.node(
                        ProvenanceKind::Argument {
                            index: index as u32,
                        },
                        &ctx.arg_antecedents(index as u32),
                    )
                })
                .collect()
        } else {
            vec![arg0]
        };
        provenance.extend(certified.as_ref().map(|(_, certificate)| *certificate));
        if ctx.tracks_host_context_environment() {
            provenance.extend(ctx.cwd_node);
        }
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.exec"),
            resource: process.lower_resource(),
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }
    if terminal_carrier(builder, &ctx, &name, arg0) {
        return true;
    }

    match model {
        Some(model) => {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            // Under an unresolved identity the model applies through a marker
            // a consumer can find in every effect's provenance.
            let identity = unresolved_identity.then(|| {
                builder.node(
                    ProvenanceKind::ModelApplication {
                        model: UNRESOLVED_IDENTITY_MODEL.to_string(),
                    },
                    &[arg0],
                )
            });
            let model_node = model_application_node(
                builder,
                model,
                &[arg0].into_iter().chain(identity).collect::<Vec<_>>(),
            );
            let mut model_argv;
            if argv[0].as_literal().is_none() || renamed {
                model_argv = argv.to_vec();
                model_argv[0] = Word::literal(name.clone());
                ctx.argv = &model_argv;
            }
            ctx.model_stack.push(model.id());
            if unresolved_identity {
                // One arm of an unresolved choice of executable, named by the
                // launch's own words.
                let launch = argv
                    .iter()
                    .map(|word| word.as_literal().unwrap_or("?"))
                    .collect::<Vec<_>>()
                    .join(" ");
                builder.push_condition(Condition::from_source(
                    &launch,
                    effinterp_proto::ByteSpan {
                        start: 0,
                        end: launch.len() as u32,
                    },
                    effinterp_proto::ConditionKind::UnresolvedExecution,
                    0,
                    2,
                    false,
                    false,
                ));
            }
            if let Some(branches) = model_argv_branches(
                builder,
                arg0,
                ctx.argv,
                argv_union_groups,
                nest.limits.value_limits(),
            ) {
                for argv in &branches {
                    let branch_ctx = InvocationCtx {
                        argv,
                        stdin: ctx.stdin,
                        argv_provenance: ctx.argv_provenance,
                        cwd: ctx.cwd,
                        cwd_resource: ctx.cwd_resource.clone(),
                        runtime_cwd: ctx.runtime_cwd,
                        scope: ctx.scope,
                        cwd_node: ctx.cwd_node,
                        nest: ctx.nest,
                        depth: ctx.depth,
                        model_stack: ctx.model_stack.clone(),
                    };
                    model.apply(builder, &branch_ctx, model_node);
                }
            } else {
                model.apply(builder, &ctx, model_node);
            }
            if unresolved_identity {
                builder.pop_condition();
            }
            true
        }
        None => {
            if path_outcome == Some(RuntimeSourceOutcome::Selected) {
                return false;
            }
            let Some(path) = argv[0].as_literal().filter(|path| path.contains('/')) else {
                // `exec CMD ...` launched as a program (`env exec CMD`) rather
                // than read by a shell. Stock systems ship no `exec` executable,
                // so the launch either fails or reaches one on PATH; the plan
                // takes the builtin's reading and runs CMD. Options stay
                // unmodeled: the shell frontend owns their grammar.
                if argv[0].as_literal() == Some("exec")
                    && argv
                        .get(1)
                        .and_then(Word::as_literal)
                        .is_some_and(|command| !command.is_empty() && !command.starts_with('-'))
                {
                    let command = arg_node(builder, &ctx, 1);
                    let argv_provenance = ctx.argv_provenance_range(builder, 1..argv.len());
                    ctx.nest_exec(
                        builder,
                        &argv[1..],
                        cwd,
                        Some(argv_provenance.as_slice()),
                        &[arg0, command],
                    );
                    return false;
                }
                unmodeled(builder, arg0, &format!("no model for command {name:?}"));
                return false;
            };
            // An explicit executable path consumes that file even when its bytes
            // are unavailable. Keep the opaque body boundary below; the read
            // and execution describe the launch, not inferred file contents.
            let selector_node = builder.node(
                ProvenanceKind::ModelApplication {
                    model: "process/executable-file@v0".to_string(),
                },
                &[arg0],
            );
            operand_effect(
                builder,
                &ctx,
                selector_node,
                0,
                &argv[0],
                "filesystem.read",
                Default::default(),
            );
            code_execution(
                if argv.iter().all(|word| word.as_literal().is_some()) {
                    effinterp_proto::RequestAssurance::Exact
                } else {
                    effinterp_proto::RequestAssurance::Conservative
                },
                builder,
                &ctx,
                selector_node,
                Some(0),
                "file",
                Default::default(),
            );
            match ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput) {
                SourceResolution::Source { origin, source } => {
                    let Some((subject, kind, interpreter)) = shebang_subject(&source, cwd) else {
                        ctx.nest.record_unsupported_source(builder, &origin);
                        unmodeled(builder, arg0, &format!("no model for command {name:?}"));
                        return false;
                    };
                    let mut launch_argv = vec![ResourceExpr::Literal { value: interpreter }];
                    launch_argv.extend(argv.iter().map(crate::nest::word_resource));
                    let launch_evidence = [arg0, selector_node]
                        .into_iter()
                        .chain((1..argv.len()).map(|index| {
                            crate::models::common::arg_node(builder, &ctx, index as u32)
                        }))
                        .collect::<Vec<_>>();
                    let shell_launch = matches!(subject, Subject::Shell { .. });
                    if shell_launch {
                        *ctx.nest.shell_arguments.borrow_mut() =
                            Some(shell_launch_arguments(builder, &ctx, 0));
                    }
                    {
                        let source_cwd = crate::models::source_parent(&origin).to_string();
                        ctx.nest.nest(
                            builder,
                            Transition::file(subject)
                                .argv(launch_argv)
                                .origin(origin)
                                .kind(kind)
                                .source_cwd(Some(&source_cwd))
                                .runtime_cwd(ctx.runtime_cwd)
                                .cwd(ctx.cwd_resource.clone(), ctx.cwd_node),
                            &launch_evidence,
                            ctx.depth,
                        );
                    };
                    if shell_launch {
                        ctx.nest.shell_arguments.borrow_mut().take();
                    }
                }
                SourceResolution::Refused(refusal) => {
                    if let Some(detail) = source_refusal_detail(
                        builder,
                        refusal,
                        &format!("no model for command {name:?}"),
                    ) {
                        command_boundary(
                            builder,
                            arg0,
                            BoundaryReason::UNMODELED_COMMAND,
                            BoundaryClass::Unresolved,
                            &KNOWN_DOMAINS,
                            &detail,
                        );
                        if let Some(command) = crate::models::framework::dispatcher("python", path)
                        {
                            crate::models::framework::dispatch_entry_script(
                                builder, &ctx, arg0, 0, 1, command,
                            );
                        }
                    }
                }
                SourceResolution::UnsupportedEncoding => command_boundary(
                    builder,
                    arg0,
                    BoundaryReason::UNMODELED_COMMAND,
                    BoundaryClass::Unresolved,
                    &KNOWN_DOMAINS,
                    "directly executed source is not valid UTF-8",
                ),
                SourceResolution::AlreadySelected => return false,
                SourceResolution::Unavailable => {
                    unmodeled(builder, arg0, &format!("no model for command {name:?}"));
                    // An unreadable `./manage.py` is taken for Django's
                    // generated script, as `python manage.py` is.
                    if let Some(command) = crate::models::framework::dispatcher("python", path) {
                        crate::models::framework::dispatch_entry_script(
                            builder, &ctx, arg0, 0, 1, command,
                        );
                    }
                }
            }
            false
        }
    }
}

/// What a PATH search established for a slash-free argv[0].
struct PathSelection {
    /// The source-selection outcome; `None` lets the basename model run.
    outcome: Option<RuntimeSourceOutcome>,
    /// The executable the search certified, and the certificate node.
    certified: Option<(String, ProvenanceRef)>,
}

/// The model a PATH-search certificate names.
pub const PATH_SEARCH_MODEL: &str = "process/path-search@v0";

/// The marker a basename model applies through when the PATH search left the
/// executable's identity unresolved.
pub const UNRESOLVED_IDENTITY_MODEL: &str = "process/unresolved-identity@v0";

fn select_path_executable(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    provenance: ProvenanceRef,
    command_search_path: Option<ResourceExpr>,
) -> PathSelection {
    let unsearched = |outcome| PathSelection {
        outcome,
        certified: None,
    };
    let Some(command) = ctx.argv[0]
        .as_literal()
        .filter(|command| !command.contains('/'))
    else {
        return unsearched(None);
    };
    let path = match command_search_path.or_else(|| ctx.environment_value("PATH")) {
        Some(ResourceExpr::Literal { value }) => value,
        Some(_) => {
            runtime_unobserved_input(
                builder,
                ctx,
                command,
                ExecutionInputRole::ExplicitInvocation,
                ExecutionPhase::Main,
                ExecutionSelector::SearchPath,
                ExecutionInputReason::Ambiguous,
            );
            return unsearched(Some(RuntimeSourceOutcome::Boundary));
        }
        None => return unsearched(None),
    };
    let candidates = path
        .split(':')
        .map(|directory| {
            if directory.is_empty() {
                command.to_string()
            } else {
                format!("{directory}/{command}")
            }
        })
        .collect();
    if builder.is_host_realm() && builder.budget().observations.is_some() {
        return certified_path_search(builder, ctx, provenance, command, candidates);
    }
    unsearched(Some(runtime_searched_source(
        builder,
        ctx,
        provenance,
        command,
        candidates,
        ExecutionInputRole::ExplicitInvocation,
        ExecutionPhase::Main,
        ExecutionSelector::SearchPath,
        RuntimeSourceLanguage::Executable,
        true,
    )))
}

/// Search PATH through host observations of each candidate, in order. The
/// first candidate that exists must be an executable file, and every earlier
/// one must be observed absent: that order proof certifies the executable,
/// and the certificate node names it with the observations as antecedents.
/// Each observation charges the analysis's `max_observation_requests`, so a
/// PATH longer than what remains of that bound ends in a limit boundary.
///
/// A candidate this plan wrote, created, moved or deleted before the launch,
/// one the host did not answer, and one that is not an executable file leave
/// the identity unresolved with a named boundary, and like any search that
/// does not establish its executable, keep the basename model from applying.
/// A search that finds nothing claims nothing either.
///
/// A certified file whose bytes read as source is a script and is analyzed
/// as one. A binary's bytes are not program source, and an unreadable file is
/// not an unrecoverable source: the basename model describes either, with
/// the certified path as its identity.
fn certified_path_search(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    arg0: ProvenanceRef,
    command: &str,
    candidates: Vec<String>,
) -> PathSelection {
    use crate::builder::WrittenSource;
    use effinterp_proto::{
        Fact, ObservationOutcome, ObservationQuery, ObservationRefusal, PathKind,
    };
    // Lexical reach: a mutation of the path, a directory above it, or a
    // selection that may contain it.
    let unchanged = |builder: &PlanBuilder, path: &str| {
        matches!(
            builder.written_source(path, |_, _| false),
            WrittenSource::Host
        )
    };
    let unresolved = PathSelection {
        outcome: Some(RuntimeSourceOutcome::Boundary),
        certified: None,
    };
    let mut proof = vec![arg0];
    let mut searched = std::collections::BTreeSet::new();
    for candidate in candidates {
        // An absolute directory needs no cwd; a relative one needs a known one.
        let Some(path) = crate::paths::join_file(ctx.runtime_cwd, &candidate)
            .filter(|path| path.starts_with('/'))
        else {
            unresolved_search(
                builder,
                &proof,
                &candidate,
                "relative to an unknown cwd",
                None,
            );
            return unresolved;
        };
        if !searched.insert(path.clone()) {
            continue;
        }
        let outcome = if unchanged(builder, &path) {
            builder.budget().observe_path(&path)
        } else {
            ObservationOutcome::Refused(ObservationRefusal::Stale)
        };
        let node = builder.node(
            ProvenanceKind::HostObservation {
                query: ObservationQuery::Path { path: path.clone() },
                outcome: outcome.clone(),
            },
            &[arg0],
        );
        proof.push(node);
        let identity = match &outcome {
            ObservationOutcome::Path(fact) if fact.kind == PathKind::Missing => continue,
            ObservationOutcome::Refused(refusal) => {
                let limit = match refusal {
                    ObservationRefusal::Limit { limit } => Some(limit.clone()),
                    _ => None,
                };
                unresolved_search(builder, &proof, &path, refusal.code(), limit);
                return unresolved;
            }
            // A listing never answers a path query.
            ObservationOutcome::Listing(_) => {
                unresolved_search(
                    builder,
                    &proof,
                    &path,
                    ObservationRefusal::Invalid.code(),
                    None,
                );
                return unresolved;
            }
            // Only a link has a final component to follow; any other file is
            // its own entry, as `follow_final_link` reads it.
            ObservationOutcome::Path(fact) => match (&fact.followed, fact.executable) {
                (Fact::Known(target), Some(true)) if target.kind == Fact::Known(PathKind::File) => {
                    Some(target.path.clone())
                }
                (Fact::Unavailable(_), Some(true)) if fact.kind == PathKind::File => {
                    Some(fact.entry.clone())
                }
                _ => None,
            },
        };
        let Some(identity) = identity else {
            unresolved_search(
                builder,
                &proof,
                &path,
                "not an observed executable file",
                None,
            );
            return unresolved;
        };
        if !unchanged(builder, &identity) {
            unresolved_search(builder, &proof, &identity, "stale", None);
            return unresolved;
        }
        let certificate = builder.node(
            ProvenanceKind::ModelApplication {
                model: PATH_SEARCH_MODEL.to_string(),
            },
            &proof,
        );
        let script = matches!(
            ctx.nest.observe_source_search(
                builder,
                &[(crate::SourceNamespace::Host, path.clone())],
                SourcePurpose::ExecutableInput,
            ),
            crate::nest::SourceSearchObservation::Found { bytes, .. }
                if std::str::from_utf8(&bytes).is_ok()
        );
        let outcome = script.then(|| {
            runtime_searched_source(
                builder,
                ctx,
                certificate,
                command,
                vec![path],
                ExecutionInputRole::ExplicitInvocation,
                ExecutionPhase::Main,
                ExecutionSelector::SearchPath,
                RuntimeSourceLanguage::Executable,
                true,
            )
        });
        return PathSelection {
            outcome,
            certified: Some((identity, certificate)),
        };
    }
    PathSelection {
        outcome: Some(RuntimeSourceOutcome::Missing),
        certified: None,
    }
}

fn unresolved_search(
    builder: &mut PlanBuilder,
    proof: &[ProvenanceRef],
    candidate: &str,
    cause: &str,
    limit: Option<String>,
) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
            class: if limit.is_some() {
                BoundaryClass::Limit
            } else {
                BoundaryClass::Unresolved
            },
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new("process")],
            affected_resource: None,
            callee: None,
            provenance: proof.to_vec(),
            limit,
            detail: Some(format!(
                "executable identity unresolved: PATH candidate {candidate}: {cause}"
            )),
        },
        CoverageLevel::Partial,
    );
}

fn native_loader_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    provenance: ProvenanceRef,
) {
    let Some(value) = ctx.environment_value("LD_PRELOAD") else {
        return;
    };
    let ResourceExpr::Literal { value } = value else {
        runtime_unobserved_input(
            builder,
            ctx,
            "$LD_PRELOAD",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::NativeLoader,
            ExecutionSelector::Environment {
                variable: "LD_PRELOAD".to_string(),
            },
            ExecutionInputReason::Ambiguous,
        );
        return;
    };
    if builder.is_host_realm()
        && ctx.argv[0]
            .as_literal()
            .filter(|command| command.contains('/'))
            .map(|command| crate::paths::resolve_fs_path(command, ctx.runtime_cwd))
            .is_some_and(|resource| {
                let ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                } = resource
                else {
                    return false;
                };
                path.starts_with('/')
                    && ctx
                        .nest
                        .context
                        .is_some_and(|context| context.secure_execution.get(&path) == Some(&true))
            })
    {
        runtime_unobserved_input(
            builder,
            ctx,
            &value,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::NativeLoader,
            ExecutionSelector::Environment {
                variable: "LD_PRELOAD".to_string(),
            },
            ExecutionInputReason::Ambiguous,
        );
        return;
    }
    for preload in value
        .split(|character: char| character == ':' || character.is_ascii_whitespace())
        .filter(|preload| !preload.is_empty())
    {
        if !preload.contains('/') || preload.contains(['$', '`']) {
            runtime_unobserved_input(
                builder,
                ctx,
                preload,
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::NativeLoader,
                ExecutionSelector::Environment {
                    variable: "LD_PRELOAD".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            continue;
        }
        runtime_selected_source(
            builder,
            ctx,
            provenance,
            preload,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::NativeLoader,
            ExecutionSelector::Environment {
                variable: "LD_PRELOAD".to_string(),
            },
            RuntimeSourceLanguage::Opaque,
        );
    }
}

/// Expand finite words whose alternatives can change option parsing. Union
/// groups correlate repeated uses of one shell binding without correlating
/// structurally equal values from independent bindings. Ordinary operand
/// unions stay intact so models can preserve them as union resources.
fn model_argv_branches(
    builder: &mut PlanBuilder,
    provenance: ProvenanceRef,

    argv: &[Word],
    argv_union_groups: Option<&[Option<ProvenanceRef>]>,
    value_limits: crate::ValueLimits,
) -> Option<Vec<Vec<Word>>> {
    let mut grouped = vec![false; argv.len()];
    let mut option_unions = Vec::<(Vec<usize>, Vec<Word>)>::new();
    for (index, word) in argv.iter().enumerate() {
        if grouped[index] {
            continue;
        }
        let [WordPart::Union(alternatives)] = word.parts.as_slice() else {
            continue;
        };
        if alternatives.iter().any(|alternative| {
            alternative
                .as_literal()
                .is_some_and(|text| text.starts_with('-') && text.len() > 1)
        }) {
            let group = argv_union_groups
                .and_then(|groups| groups.get(index))
                .copied()
                .flatten();
            let positions: Vec<_> = argv
                .iter()
                .enumerate()
                .filter(|(candidate, candidate_word)| {
                    !grouped[*candidate]
                        && *candidate_word == word
                        && argv_union_groups
                            .and_then(|groups| groups.get(*candidate))
                            .copied()
                            .flatten()
                            == group
                })
                .map(|(candidate, _)| candidate)
                .collect();
            for position in &positions {
                grouped[*position] = true;
            }
            option_unions.push((positions, alternatives.clone()));
        }
    }
    if option_unions.is_empty() {
        return None;
    }

    let max_cardinality = value_limits.max_cardinality;
    let mut branches = vec![argv.to_vec()];
    for (positions, alternatives) in &option_unions {
        if branches.len().saturating_mul(alternatives.len()) > max_cardinality {
            command_boundary(
                builder,
                provenance,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                &crate::builder::KNOWN_DOMAINS,
                "option alternatives exceed bounded operation selection",
            );

            return Some(vec![argv.iter().map(widen_option_union).collect()]);
        }
        let mut expanded = Vec::with_capacity(branches.len() * alternatives.len());
        for branch in branches {
            for alternative in alternatives {
                let mut branch = branch.clone();
                for position in positions {
                    branch[*position] = alternative.clone();
                }
                expanded.push(branch);
            }
        }
        branches = expanded;
    }
    Some(branches)
}

fn widen_option_union(word: &Word) -> Word {
    let [WordPart::Union(alternatives)] = word.parts.as_slice() else {
        return word.clone();
    };
    if !alternatives.iter().any(|alternative| {
        alternative
            .as_literal()
            .is_some_and(|text| text.starts_with('-') && text.len() > 1)
    }) {
        return word.clone();
    }
    let operands: Vec<_> = alternatives
        .iter()
        .filter(|alternative| {
            !alternative
                .as_literal()
                .is_some_and(|text| text.starts_with('-') && text.len() > 1)
        })
        .cloned()
        .collect();
    match operands.as_slice() {
        [] => Word::new(vec![WordPart::Unknown]),
        [operand] => operand.clone(),
        _ => Word::new(vec![WordPart::Union(operands)]),
    }
}

/// Interpreter named by the first line, including an env shebang wrapper.
pub(crate) fn shebang_interpreter(source: &str) -> Option<&str> {
    let shebang = source.lines().next()?.strip_prefix("#!")?.trim();
    let mut words = shebang.split_whitespace();
    let mut interpreter = words.next()?;
    if interpreter.rsplit('/').next()? == "env" {
        interpreter = words.find(|word| !word.starts_with('-'))?;
    }
    Some(interpreter)
}

pub(crate) fn shebang_subject(
    source: &str,
    cwd: Option<&str>,
) -> Option<(Subject, ExecutionEdgeKind, String)> {
    use effinterp_proto::{ExecutionEdgeKind, SourceDialect};

    let interpreter = shebang_interpreter(source)?;
    let cwd = cwd.map(str::to_string);
    let subject = match interpreter.rsplit('/').next()? {
        "sh" | "bash" | "dash" | "zsh" => Subject::Shell {
            source: source.to_string(),
            cwd,
            context: Default::default(),
        },
        interpreter
            if matches!(interpreter, "python" | "python2" | "python3")
                || interpreter
                    .strip_prefix("python2.")
                    .or_else(|| interpreter.strip_prefix("python3."))
                    .is_some_and(|suffix| {
                        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
                    }) =>
        {
            Subject::Source {
                dialect: None,
                language: "python".into(),
                source: source.to_string(),
                cwd,
                context: Default::default(),
            }
        }
        "node" | "nodejs" | "tsx" | "ts-node" | "bun" | "deno" => Subject::Source {
            language: "js".into(),
            source: source.to_string(),
            dialect: Some(
                if matches!(interpreter.rsplit('/').next()?, "tsx" | "ts-node") {
                    SourceDialect::Ts
                } else {
                    SourceDialect::Js
                },
            ),
            cwd,
            context: Default::default(),
        },
        "php" | "php7" | "php8" => Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: source.to_string(),
            cwd,
            context: Default::default(),
        },
        "ruby" => Subject::Source {
            dialect: None,
            language: "ruby".to_string(),
            source: source.to_string(),
            cwd,
            context: Default::default(),
        },
        _ => return None,
    };
    let kind = if matches!(subject, Subject::Shell { .. }) {
        ExecutionEdgeKind::Script
    } else {
        ExecutionEdgeKind::Interpreter
    };
    Some((subject, kind, interpreter.to_string()))
}

pub(crate) fn unmodeled(builder: &mut PlanBuilder, arg0: ProvenanceRef, detail: &str) {
    command_boundary(
        builder,
        arg0,
        BoundaryReason::UNMODELED_COMMAND,
        BoundaryClass::Unmodeled,
        &KNOWN_DOMAINS,
        detail,
    );
}

fn unresolved(builder: &mut PlanBuilder, arg0: ProvenanceRef, detail: &str) {
    command_boundary(
        builder,
        arg0,
        BoundaryReason::UNRESOLVED_COMMAND,
        BoundaryClass::Unresolved,
        &KNOWN_DOMAINS,
        detail,
    );
}

fn command_boundary(
    builder: &mut PlanBuilder,
    arg0: ProvenanceRef,
    reason: BoundaryReason,
    class: BoundaryClass,
    domains: &[&str],
    detail: &str,
) {
    // The unresolved or unmodeled head leaves process partially covered.
    // Any other named domain received no downstream analysis.
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    for domain in domains {
        if *domain != "process" {
            builder.declare_coverage(Domain::new(*domain), CoverageLevel::None);
        }
    }
    let boundary = builder.boundary(Boundary {
        reason,
        class,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: domains
            .iter()
            .copied()
            .chain(["dataflow"])
            .map(Domain::new)
            .collect(),
        provenance: vec![arg0],
        limit: None,
        detail: Some(detail.to_string()),
    });
    builder.attach_boundary_to_uncertain_execution(boundary);
}
