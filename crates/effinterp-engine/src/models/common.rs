//! Helpers shared by command models.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionAssurance, ExecutionContent, ExecutionEdgeKind, ExecutionInputReason,
    ExecutionInputRole, ExecutionPhase, ExecutionRealm, ExecutionSelection, ExecutionSelector,
    Fact, Modality, ObservationOutcome, ObservationQuery, ObservationRefusal, Operation, PathKind,
    Port, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceFamily, ResourceIdentity,
    SourceDialect, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::{InvocationCtx, ModelBindingEnd, ModelCausalBinding};
use crate::nest::{SourceResolution, Transition};
use crate::paths::executable_identity;
use crate::word::{Word, WordPart};
use effinterp_model_schema::EffectSelection;

pub(crate) type Attrs = BTreeMap<String, AttrValue>;

/// A list attribute of every value in invocation order, or `None` when any
/// element is unknown. Callers leave an incomplete list unemitted, so a
/// matcher reads its absence as unknown rather than as a shorter list.
pub(crate) fn complete_list(
    values: impl IntoIterator<Item = Option<AttrValue>>,
) -> Option<AttrValue> {
    values
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .map(AttrValue::List)
}

/// Marks a parsed content-file operand without changing unrelated filesystem reads.
pub(crate) fn program_input_attrs() -> Attrs {
    BTreeMap::from([(
        "access_purpose".into(),
        AttrValue::String("program_input".into()),
    )])
}

pub(crate) fn program_output_attrs() -> Attrs {
    BTreeMap::from([("disclosure".into(), AttrValue::String("contents".into()))])
}

/// Retain a configuration lookup even when its current value is absent, so
/// callers can observe the named input before relying on the analyzed route.
pub(crate) fn environment_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    name: &str,
) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "Only selected command configuration environment inputs are modeled".into(),
            ),
        },
        CoverageLevel::Partial,
    );
    arg_effect(
        builder,
        ctx,
        model_node,
        0,
        "environment.read",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
        },
        Default::default(),
    );
}

/// Frontend used for one runtime-selected byte buffer.
#[derive(Clone, Copy)]
pub(crate) enum RuntimeSourceLanguage {
    Shell,
    Python,
    PythonModule,
    JavaScript(SourceDialect),
    Source(&'static str),
    Executable,
    Opaque,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeSourceOutcome {
    Selected,
    Missing,
    Boundary,
}

impl RuntimeSourceLanguage {
    fn purpose(self) -> SourcePurpose {
        if matches!(self, Self::Executable) {
            SourcePurpose::ExecutableInput
        } else {
            SourcePurpose::InvocationInput
        }
    }
}

/// Resolve and analyze one directly named runtime-selected source.
#[allow(clippy::too_many_arguments)]
pub(crate) fn runtime_selected_source(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    request: &str,
    role: ExecutionInputRole,
    phase: ExecutionPhase,
    selector: ExecutionSelector,
    language: RuntimeSourceLanguage,
) -> bool {
    let component = runtime_component(ctx);
    let purpose = language.purpose();
    let mut input = ctx.nest.source_input(
        builder,
        request,
        purpose,
        ExecutionContent::Unobserved {
            reason: ExecutionInputReason::ResolverUnavailable,
        },
        &component,
    );
    input.role = role;
    input.phase = phase;
    input.selector = selector;
    input.selection = ExecutionSelection::Direct {
        request: request.to_string(),
    };
    let Some((namespace, path)) = crate::paths::join_source_path(ctx.runtime_cwd, request) else {
        input.selected = None;
        input.assurance = ExecutionAssurance::Widened;
        input.content = ExecutionContent::Unobserved {
            reason: ExecutionInputReason::NamespaceDenied,
        };
        ctx.nest.record_input_boundary(builder, request, input);
        return false;
    };
    input.selected = Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: path.clone() },
    });
    let resolved = ctx
        .nest
        .resolve_execution_input(builder, path, namespace, purpose, input);
    analyze_runtime_source(builder, ctx, model_node, phase, language, resolved)
}

/// Resolve an ordered runtime search and analyze its first observed winner.
#[allow(clippy::too_many_arguments)]
pub(crate) fn runtime_searched_source(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    request: &str,
    candidates: Vec<String>,
    role: ExecutionInputRole,
    phase: ExecutionPhase,
    selector: ExecutionSelector,
    language: RuntimeSourceLanguage,
    record_missing: bool,
) -> RuntimeSourceOutcome {
    let component = runtime_component(ctx);
    let purpose = language.purpose();
    let mut input = ctx.nest.source_input(
        builder,
        request,
        purpose,
        ExecutionContent::Unobserved {
            reason: ExecutionInputReason::ResolverUnavailable,
        },
        &component,
    );
    input.role = role;
    input.phase = phase;
    input.selector = selector;
    let mut seen = std::collections::BTreeSet::new();
    let candidates = candidates
        .into_iter()
        .filter_map(|candidate| crate::paths::join_source_path(ctx.runtime_cwd, &candidate))
        .filter(|(_, path)| seen.insert(path.clone()))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        if !record_missing {
            return RuntimeSourceOutcome::Missing;
        }
        input.selected = None;
        input.assurance = ExecutionAssurance::Widened;
        input.content = ExecutionContent::Unobserved {
            reason: ExecutionInputReason::NamespaceDenied,
        };
        ctx.nest.record_input_boundary(builder, request, input);
        return RuntimeSourceOutcome::Boundary;
    }
    let (resolved, exhausted) =
        ctx.nest
            .resolve_execution_search(builder, candidates, purpose, input, record_missing);
    if exhausted {
        return RuntimeSourceOutcome::Missing;
    }
    match resolved {
        SourceResolution::Source { .. } => {
            analyze_runtime_source(builder, ctx, model_node, phase, language, resolved);
            RuntimeSourceOutcome::Selected
        }
        SourceResolution::UnsupportedEncoding | SourceResolution::AlreadySelected => {
            RuntimeSourceOutcome::Selected
        }
        SourceResolution::Refused(_) | SourceResolution::Unavailable => {
            RuntimeSourceOutcome::Boundary
        }
    }
}

/// Retain a selector whose winner cannot be observed safely.
pub(crate) fn runtime_unobserved_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    request: &str,
    role: ExecutionInputRole,
    phase: ExecutionPhase,
    selector: ExecutionSelector,
    reason: ExecutionInputReason,
) {
    runtime_unobserved_input_scoped(builder, ctx, request, role, phase, selector, reason, None);
}

/// Retain a selector with uncertainty confined to its declared effect domains.
#[allow(clippy::too_many_arguments)]
pub(crate) fn runtime_unobserved_input_scoped(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    request: &str,
    role: ExecutionInputRole,
    phase: ExecutionPhase,
    selector: ExecutionSelector,
    reason: ExecutionInputReason,
    domains: Option<&[&str]>,
) {
    let component = runtime_component(ctx);
    let mut input = ctx.nest.source_input(
        builder,
        request,
        SourcePurpose::InvocationInput,
        ExecutionContent::Unobserved { reason },
        &component,
    );
    input.role = role;
    input.phase = phase;
    input.selector = selector;
    input.selected = None;
    input.assurance = ExecutionAssurance::Widened;
    input.selection = ExecutionSelection::Direct {
        request: request.to_string(),
    };
    ctx.nest
        .record_input_boundary_scoped(builder, request, input, domains);
}

fn runtime_component(ctx: &InvocationCtx<'_>) -> String {
    ctx.argv[0]
        .as_literal()
        .and_then(|command| command.rsplit('/').next())
        .unwrap_or("runtime")
        .to_string()
}

fn analyze_runtime_source(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    phase: ExecutionPhase,
    language: RuntimeSourceLanguage,
    resolved: SourceResolution,
) -> bool {
    if matches!(resolved, SourceResolution::AlreadySelected) {
        return true;
    }
    let SourceResolution::Source { origin, source } = resolved else {
        return false;
    };
    // CommonJS file search can select data or native code, neither of which
    // may be interpreted as JavaScript source.
    if matches!(language, RuntimeSourceLanguage::JavaScript(_))
        && matches!(
            std::path::Path::new(&origin)
                .extension()
                .and_then(|ext| ext.to_str()),
            Some("json" | "node")
        )
    {
        ctx.nest.record_unsupported_source(builder, &origin);
        return true;
    }
    if matches!(language, RuntimeSourceLanguage::PythonModule) && !origin.ends_with(".py") {
        ctx.nest.record_unsupported_source(builder, &origin);
        return true;
    }
    let mut launch_argv = Vec::new();
    let subject = match language {
        RuntimeSourceLanguage::Shell => Subject::Shell {
            source,
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        RuntimeSourceLanguage::Python | RuntimeSourceLanguage::PythonModule => Subject::Source {
            dialect: None,
            language: "python".into(),
            source,
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        RuntimeSourceLanguage::JavaScript(dialect) => Subject::Source {
            language: "js".into(),
            source,
            dialect: Some(dialect),
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        RuntimeSourceLanguage::Source(language) => Subject::Source {
            dialect: None,
            language: language.to_string(),
            source,
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        RuntimeSourceLanguage::Executable => {
            let Some((subject, _, interpreter)) = crate::exec::shebang_subject(&source, ctx.cwd)
            else {
                ctx.nest.record_unsupported_source(builder, &origin);
                return true;
            };
            launch_argv.push(ResourceExpr::Literal { value: interpreter });
            launch_argv.extend(ctx.argv.iter().map(crate::nest::word_resource));
            subject
        }
        RuntimeSourceLanguage::Opaque => {
            ctx.nest.record_unsupported_source(builder, &origin);
            return true;
        }
    };
    let mut launch_evidence = vec![model_node];
    if !launch_argv.is_empty() {
        launch_evidence
            .extend((0..ctx.argv.len()).map(|index| arg_node(builder, ctx, index as u32)));
    }
    let shell_launch = matches!(subject, Subject::Shell { .. }) && phase == ExecutionPhase::Main;
    if shell_launch {
        *ctx.nest.shell_arguments.borrow_mut() = Some(shell_launch_arguments(builder, ctx, 0));
    }
    {
        let source_cwd = crate::models::source_parent(&origin).to_string();
        ctx.nest.nest(
            builder,
            Transition::file(subject)
                .argv(launch_argv)
                .origin(origin)
                .kind(runtime_selection_edge(phase))
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
    true
}

fn runtime_selection_edge(phase: ExecutionPhase) -> ExecutionEdgeKind {
    match phase {
        ExecutionPhase::Main => ExecutionEdgeKind::Launch,
        ExecutionPhase::Startup => ExecutionEdgeKind::Startup,
        ExecutionPhase::Preload => ExecutionEdgeKind::Preload,
        ExecutionPhase::Import => ExecutionEdgeKind::Import,
        ExecutionPhase::NativeLoader => ExecutionEdgeKind::NativeLoader,
        ExecutionPhase::BuildHook => ExecutionEdgeKind::BuildHook,
        ExecutionPhase::PackageHook => ExecutionEdgeKind::PackageHook,
        ExecutionPhase::VcsHook => ExecutionEdgeKind::VcsHook,
        ExecutionPhase::Plugin => ExecutionEdgeKind::Plugin,
    }
}

pub(crate) fn stdin_stdout_binding() -> ModelCausalBinding {
    ModelCausalBinding {
        assurance: effinterp_proto::CausalAssurance::Conservative,
        from: ModelBindingEnd::Port(Port::Stdin),
        to: ModelBindingEnd::Port(Port::Stdout),
    }
}

pub(crate) fn filesystem_read_stdout_binding() -> ModelCausalBinding {
    ModelCausalBinding {
        assurance: effinterp_proto::CausalAssurance::Conservative,
        from: ModelBindingEnd::Effect {
            operation: "filesystem.read".to_string(),
            selection: EffectSelection::All,
        },
        to: ModelBindingEnd::Port(Port::Stdout),
    }
}

pub(crate) fn operands_read_stdin(operands: &[(u32, &Word)]) -> bool {
    operands.is_empty()
        || operands
            .iter()
            .any(|(_, operand)| operand.as_literal() == Some("-"))
}

/// Lower a symbolic command operand without assigning it to a concrete
/// resource identity.
pub(crate) fn symbolic_expr(word: &Word, family: &str) -> ResourceExpr {
    let mut parts = word
        .parts
        .iter()
        .map(|part| match part {
            WordPart::Literal(value) => ResourceExpr::Literal {
                value: value.clone(),
            },
            WordPart::Env(name) => ResourceExpr::Environment { name: name.clone() },
            WordPart::Value(value) => value.clone(),
            WordPart::Glob(_) | WordPart::Union(_) | WordPart::Unknown => {
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new(family),
                }
            }
        })
        .collect::<Vec<_>>();
    if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        ResourceExpr::Join { parts }
    }
}

/// Build a remote network endpoint while preserving symbolic host parts.
pub(crate) fn remote_endpoint(host_parts: Vec<WordPart>, scheme: &str) -> ResourceExpr {
    let host = Word::new(host_parts);
    if let Some(host) = host.as_literal() {
        return ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: host.rsplit('@').next().unwrap_or(host).to_string(),
                scheme: Some(scheme.to_string()),
                port: None,
                path: None,
            },
        };
    }
    let mut parts = vec![ResourceExpr::Literal {
        value: format!("{scheme}://"),
    }];
    match symbolic_expr(&host, "network") {
        ResourceExpr::Join { parts: host_parts } => parts.extend(host_parts),
        host => parts.push(host),
    }
    ResourceExpr::Join { parts }
}

/// Whether a word contains text that cannot safely be rendered for a shell to
/// parse again.
pub(crate) fn has_unknown(word: &Word) -> bool {
    word.parts.iter().any(|part| {
        matches!(
            part,
            WordPart::Value(_) | WordPart::Union(_) | WordPart::Unknown
        )
    })
}

/// Analyze source handed to a remote shell without resolving its paths or
/// environment against the local host.
pub(crate) fn nest_remote_shell(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    source: String,
    endpoint: String,
) {
    ctx.nest.nest(
        builder,
        Transition::file(Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .kind(ExecutionEdgeKind::Launch)
        .realm(ExecutionRealm::Remote { endpoint })
        .source_cwd(None)
        .runtime_cwd(None)
        .cwd(Some(ResourceExpr::Parameter { name: "cwd".into() }), None),
        provenance,
        ctx.depth,
    );
}

/// Whether a leading symbolic operand has no literal evidence that fixes it
/// to one side of a transfer.
pub(crate) fn leading_symbolic_without(word: &Word, separators: &[char]) -> bool {
    word.parts
        .first()
        .is_some_and(|part| !matches!(part, WordPart::Literal(_)))
        && !word
            .parts
            .iter()
            .any(|part| matches!(part, WordPart::Literal(value) if value.contains(separators)))
}

pub(crate) fn credential_full(builder: &mut PlanBuilder) {
    builder.declare_coverage(Domain::new("credential"), CoverageLevel::Full);
}

pub(crate) fn system_full(builder: &mut PlanBuilder) {
    builder.declare_coverage(Domain::new("system"), CoverageLevel::Full);
}

pub(crate) fn fs_full_no_spawn(builder: &mut PlanBuilder) {
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
}

/// Shell launch arguments starting with `$0`, retaining each word's provenance.
pub(crate) fn shell_launch_arguments(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    start: usize,
) -> Vec<(Word, ProvenanceRef)> {
    ctx.argv[start..]
        .iter()
        .enumerate()
        .map(|(offset, word)| {
            (
                word.clone(),
                arg_node(builder, ctx, (start + offset) as u32),
            )
        })
        .collect()
}

/// Apply initial-state path evidence to one filesystem resource whose
/// operation reaches the file its final path component points at: a
/// redirection, or a command that consumes the operand's contents. Link
/// creation, rename, unlink and metadata operations name the entry itself and
/// never come here.
///
/// Only a concrete absolute host path names one entry to ask about; a
/// symbolic, patterned or relative resource does not. A known identity
/// replaces the lexical spelling *before* the effect is recorded, so every
/// later keying — flow frontiers, transfer pairing, effect identity — sees one
/// resource for one file. An unanswered demand keeps the operand's own
/// evidence, marks physical identity unresolved, and never erases the effect.
///
/// Two kinds of evidence answer here, in order. A path this invocation
/// created as a link is not in the host's initial snapshot at all, so the
/// plan's own creation evidence follows it. An exact move carries the source's
/// observed identity without asking the host about the now-obsolete source or
/// destination state. Everything else is the host's to answer.
///
/// Returns the invocation evidence used and the observation node when one was
/// minted.
pub(crate) fn follow_final_link(
    builder: &mut PlanBuilder,
    resource: &mut ResourceExpr,
    use_site: &[ProvenanceRef],
) -> Vec<ProvenanceRef> {
    let (mut nodes, observe_host) = builder.follow_created_content_identity(resource);
    if !observe_host {
        return nodes;
    }
    let budget = builder.budget();
    // No channel: the engine asks nothing, claims no identity, and leaves the
    // plan the byte-only entry points produce. Other realms are not this
    // host's namespace, so their paths are not askable either.
    if budget.observations.is_none() || !builder.is_host_realm() {
        return nodes;
    }
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = &*resource
    else {
        return nodes;
    };
    if !path.starts_with('/') {
        return nodes;
    }
    let path = path.clone();
    let outcome = budget.observe_path(&path);
    let node = builder.node(
        ProvenanceKind::HostObservation {
            query: ObservationQuery::Path { path: path.clone() },
            outcome: outcome.clone(),
        },
        use_site,
    );
    let unavailable = match &outcome {
        ObservationOutcome::Refused(refusal) => Some(refusal),
        // A listing never answers a path query.
        ObservationOutcome::Listing(_) => Some(&ObservationRefusal::Invalid),
        ObservationOutcome::Path(fact) => {
            let identity = match &fact.followed {
                Fact::Known(target) => Some(target.path.as_str()),
                // Only a link has a final component to follow. For every other
                // entry the observed entry identity is the identity, so an
                // absent target component leaves nothing this use needed
                // unanswered — and the ancestors the host already resolved are
                // exactly the uncertainty the lexical spelling carried before.
                Fact::Unavailable(_) if fact.kind != PathKind::Symlink => Some(fact.entry.as_str()),
                Fact::Unavailable(_) => None,
            };
            match identity {
                Some(identity) => {
                    if identity != path {
                        *resource = ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: identity.to_string(),
                            },
                        };
                    }
                    None
                }
                None => match &fact.followed {
                    Fact::Unavailable(refusal) => Some(refusal),
                    Fact::Known(_) => None,
                },
            }
        }
    };
    if let Some(refusal) = unavailable {
        let (class, limit) = match refusal {
            // A bound that saturated is not a denial, and its real name is the
            // one the host or the engine charged.
            ObservationRefusal::Limit { limit } => (BoundaryClass::Limit, Some(limit.clone())),
            _ => (BoundaryClass::Unresolved, None),
        };
        let detail = format!("path identity unobserved: {}", refusal.code());
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                class,
                scope: BoundaryScope::Invocation,
                domains: vec![Domain::new("filesystem")],
                affected_resource: Some(resource.clone()),
                callee: None,
                provenance: vec![node],
                limit,
                detail: Some(detail),
            },
            CoverageLevel::Partial,
        );
    }
    nodes.push(node);
    nodes
}

/// The canonical path of an existing absolute `path`, every link followed,
/// with the observation node that establishes it; `None` when the host does
/// not establish it or shows nothing there.
pub(crate) fn observed_canonical_path(
    builder: &mut PlanBuilder,
    path: &str,
    use_site: &[ProvenanceRef],
) -> Option<(String, ProvenanceRef)> {
    if !path.starts_with('/') || builder.budget().observations.is_none() || !builder.is_host_realm()
    {
        return None;
    }
    let outcome = builder.budget().observe_path(path);
    let ObservationOutcome::Path(fact) = &outcome else {
        return None;
    };
    let canonical = match (&fact.followed, fact.kind) {
        (Fact::Known(target), _) if !matches!(target.kind, Fact::Known(PathKind::Missing)) => {
            target.path.clone()
        }
        (_, PathKind::Missing | PathKind::Symlink) => return None,
        _ => fact.entry.clone(),
    };
    let node = builder.node(
        ProvenanceKind::HostObservation {
            query: ObservationQuery::Path {
                path: path.to_string(),
            },
            outcome,
        },
        use_site,
    );
    Some((canonical, node))
}

/// The physical path of the directory `cwd` names, as `pwd -P` prints it: the
/// host's resolved entry, through a final link to its target. When the host
/// cannot answer, the lexical spelling may hide a link, so the value is
/// unresolved and a boundary says why. So is a path the host shows is not a
/// directory: a `cd` there failed or searched `CDPATH`, and either way the
/// shell is elsewhere.
pub(crate) fn physical_directory(
    builder: &mut PlanBuilder,
    cwd: &ResourceExpr,
    use_site: &[ProvenanceRef],
) -> ResourceExpr {
    let path = match cwd {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path.starts_with('/') => Some(path.clone()),
        _ => None,
    };
    let observed = path
        .as_ref()
        .filter(|_| builder.budget().observations.is_some() && builder.is_host_realm())
        .map(|path| (path.clone(), builder.budget().observe_path(path)));
    // `None` when the host answered that the path is not a directory.
    let (refusal, provenance) = match observed {
        Some((path, outcome)) => {
            let node = builder.node(
                ProvenanceKind::HostObservation {
                    query: ObservationQuery::Path { path },
                    outcome: outcome.clone(),
                },
                use_site,
            );
            match outcome {
                ObservationOutcome::Path(fact) => match (fact.kind, fact.followed) {
                    (PathKind::Symlink, Fact::Known(target)) => {
                        return ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: target.path },
                        };
                    }
                    (PathKind::Symlink, Fact::Unavailable(refusal)) => (Some(refusal), vec![node]),
                    (PathKind::Directory, _) => {
                        return ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: fact.entry },
                        };
                    }
                    _ => (None, vec![node]),
                },
                ObservationOutcome::Refused(refusal) => (Some(refusal), vec![node]),
                // A listing never answers a path query.
                ObservationOutcome::Listing(_) => (Some(ObservationRefusal::Invalid), vec![node]),
            }
        }
        None => (Some(ObservationRefusal::Unobserved), use_site.to_vec()),
    };
    let (class, limit) = match &refusal {
        Some(ObservationRefusal::Limit { limit }) => (BoundaryClass::Limit, Some(limit.clone())),
        _ => (BoundaryClass::Unresolved, None),
    };
    let detail = match &refusal {
        Some(refusal) => format!("physical working directory unobserved: {}", refusal.code()),
        None => "physical working directory is not a directory".to_string(),
    };
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
            class,
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new("filesystem")],
            affected_resource: Some(cwd.clone()),
            callee: None,
            provenance,
            limit,
            detail: Some(detail),
        },
        CoverageLevel::Partial,
    );
    ResourceExpr::Unresolved {
        family: ResourceFamily::new("filesystem"),
    }
}

/// What the host shows at a path a `cd` may enter.
pub(crate) enum DirectoryEntry {
    /// A directory, or a link to one: a change there succeeds.
    Directory,
    /// Missing, or not a directory: a change there fails.
    NotDirectory,
    /// No channel, another realm, a non-concrete path, or a refused question.
    Unknown,
}

/// Ask the host whether `path` is a directory a `cd` can enter. Only a
/// concrete absolute host path is askable, as for [`physical_directory`]. A
/// path this command created or moved is refused as stale, so it stays
/// unknown rather than taking the initial snapshot's answer.
pub(crate) fn directory_entry(
    builder: &mut PlanBuilder,
    path: &ResourceExpr,
    use_site: &[ProvenanceRef],
) -> DirectoryEntry {
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = path
    else {
        return DirectoryEntry::Unknown;
    };
    if !path.starts_with('/') || builder.budget().observations.is_none() || !builder.is_host_realm()
    {
        return DirectoryEntry::Unknown;
    }
    let outcome = builder.budget().observe_path(path);
    let ObservationOutcome::Path(fact) = &outcome else {
        return DirectoryEntry::Unknown;
    };
    let directory = match (fact.kind, &fact.followed) {
        (PathKind::Directory, _) => true,
        (PathKind::Symlink, Fact::Known(target)) => match target.kind {
            Fact::Known(kind) => kind == PathKind::Directory,
            Fact::Unavailable(_) => return DirectoryEntry::Unknown,
        },
        (PathKind::Symlink, Fact::Unavailable(_)) => return DirectoryEntry::Unknown,
        _ => false,
    };
    if directory {
        return DirectoryEntry::Directory;
    }
    // The plan records the fact its cwd rests on, so the observation manifest
    // re-checks it.
    builder.node(
        ProvenanceKind::HostObservation {
            query: ObservationQuery::Path { path: path.clone() },
            outcome,
        },
        use_site,
    );
    DirectoryEntry::NotDirectory
}

/// Resolve the `..` components of an absolute literal operand through the
/// host's links. `link/..` names the parent of the link's target, not the
/// directory that holds the link, so the lexical collapse the path resolver
/// performs is exact only when the component a `..` cancels is not a link.
/// Each cancelled component is asked about, after any link or move this
/// command made earlier at that path; a link continues from its target.
///
/// A trailing slash makes the final component a directory to resolve, so a
/// link there is followed too (POSIX pathname resolution): `rm -r link/`
/// empties the directory the link points at, not the link.
///
/// Returns false when the host shows a cancelled component cannot be
/// traversed: a file, a missing entry, or a link to either fails the lookup
/// (ENOTDIR or ENOENT), so the operand names nothing and the caller models
/// no effect on it. An unanswered demand leaves the operand's identity
/// unresolved rather than claiming the lexical spelling.
///
/// The observation nodes it mints answer questions about the operand's
/// ancestors, not about its own path, so they stay out of the effect's
/// provenance: the bridge reads the last path observation there as the one
/// made of the effect's resource.
pub(crate) fn follow_parent_links(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    operand: &Word,
    resource: &mut ResourceExpr,
    use_site: &[ProvenanceRef],
) -> bool {
    let Some(text) = operand.as_literal() else {
        return true;
    };
    let spelled = if text.starts_with('/') {
        text.to_string()
    } else {
        match ctx.cwd_resource() {
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) if path.starts_with('/') => format!("{path}/{text}"),
            _ => return true,
        }
    };
    let cancels = spelled
        .split('/')
        .scan(0usize, |depth, component| {
            Some(match component {
                "" | "." => false,
                ".." => std::mem::replace(depth, depth.saturating_sub(1)) > 0,
                _ => {
                    *depth += 1;
                    false
                }
            })
        })
        .any(|cancels| cancels);
    let trailing_slash = trailing_slash_follows_link(text);
    // A descriptor namespace resolves in the process that opens it, so the
    // host's answer, made in Nah's own process, does not describe it; the
    // descriptor model reads its lexical spelling.
    let per_process = ["/dev/fd/", "/proc/self/", "/proc/thread-self/"]
        .iter()
        .any(|prefix| spelled.starts_with(prefix));
    let budget = builder.budget();
    if !(cancels || trailing_slash)
        || per_process
        || budget.observations.is_none()
        || !builder.is_host_realm()
        || !matches!(
            resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { .. }
            }
        )
    {
        return true;
    }
    let components = |path: &str| -> Vec<String> {
        path.split('/')
            .filter(|component| !component.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut nodes = Vec::new();
    let mut physical: Vec<String> = Vec::new();
    let mut unavailable = None;
    for component in spelled.split('/') {
        match component {
            "" | "." => {}
            ".." if physical.is_empty() => {}
            ".." => {
                let mut entry = ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: format!("/{}", physical.join("/")),
                    },
                };
                let (created, observe_host) = builder.follow_created_content_identity(&mut entry);
                nodes.extend(created);
                let entry = match entry {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if observe_host && path.starts_with('/') => path,
                    // Content this command moved here, or a created link to
                    // no absolute path: the host's answer predates it.
                    _ => {
                        unavailable = Some(ObservationRefusal::Stale);
                        break;
                    }
                };
                physical = components(&entry);
                let outcome = budget.observe_path(&entry);
                nodes.push(builder.node(
                    ProvenanceKind::HostObservation {
                        query: ObservationQuery::Path {
                            path: entry.clone(),
                        },
                        outcome: outcome.clone(),
                    },
                    use_site,
                ));
                let fact = match outcome {
                    ObservationOutcome::Path(fact) => fact,
                    ObservationOutcome::Refused(refusal) => {
                        unavailable = Some(refusal);
                        break;
                    }
                    // A listing never answers a path query.
                    ObservationOutcome::Listing(_) => {
                        unavailable = Some(ObservationRefusal::Invalid);
                        break;
                    }
                };
                match (fact.kind, fact.followed) {
                    // The lexical collapse is exact beneath a directory.
                    (PathKind::Directory, _) => {}
                    (PathKind::Symlink, Fact::Known(target)) => match target.kind {
                        Fact::Known(PathKind::Directory) => physical = components(&target.path),
                        Fact::Known(_) => return false,
                        Fact::Unavailable(refusal) => {
                            unavailable = Some(refusal);
                            break;
                        }
                    },
                    (PathKind::Symlink, Fact::Unavailable(refusal)) => {
                        unavailable = Some(refusal);
                        break;
                    }
                    _ => return false,
                }
                physical.pop();
            }
            component => physical.push(component.to_string()),
        }
    }
    let Some(refusal) = unavailable else {
        let path = format!("/{}", physical.join("/"));
        if matches!(&*resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: lexical }
        } if *lexical != path)
        {
            *resource = ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            };
        }
        if trailing_slash {
            follow_final_link(builder, resource, use_site);
        }
        return true;
    };
    let (class, limit) = match &refusal {
        ObservationRefusal::Limit { limit } => (BoundaryClass::Limit, Some(limit.clone())),
        _ => (BoundaryClass::Unresolved, None),
    };
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
            class,
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new("filesystem")],
            affected_resource: Some(resource.clone()),
            callee: None,
            provenance: nodes,
            limit,
            detail: Some(format!(
                "parent traversal identity unobserved: {}",
                refusal.code()
            )),
        },
        CoverageLevel::Partial,
    );
    *resource = ResourceExpr::Unresolved {
        family: ResourceFamily::new("filesystem"),
    };
    true
}

/// Whether a path ends in a slash after a named final component, which makes
/// pathname resolution follow a link there to the directory it points at.
pub(crate) fn trailing_slash_follows_link(path: &str) -> bool {
    path.ends_with('/')
        && !matches!(
            path.trim_end_matches('/').rsplit('/').next(),
            Some("" | "." | "..")
        )
}

/// Whether this effect consumes the operand's contents, which reaches the
/// file the final path component points at. The declaration says so: a model
/// that marks a content-file operand is describing exactly that access.
pub(crate) fn reads_operand_contents(effect: &Effect) -> bool {
    effect.operation.as_str() == "filesystem.read"
        && matches!(
            effect.attributes.get("access_purpose"),
            Some(AttrValue::String(purpose)) if purpose == "program_input"
        )
}

/// One filesystem read of an operand whose contents the command consumes.
/// Like [`operand_effect`], with the operand's observed identity resolved
/// before the effect is recorded.
pub(crate) fn content_read_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operand: &Word,
    attributes: Attrs,
) -> Option<u32> {
    let arg = fs_arg_node(builder, ctx, index, operand);
    let mut resource = ctx.resolve_fs_word(operand);
    let observation = follow_final_link(builder, &mut resource, &[arg, model_node]);
    let mut provenance = vec![arg, model_node];
    provenance.extend(observation);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("filesystem.read"),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    })
}

/// Provenance node for one argv position of this invocation.
pub(crate) fn arg_node(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    index: u32,
) -> ProvenanceRef {
    builder.node(
        ProvenanceKind::Argument { index },
        &ctx.arg_antecedents(index),
    )
}

/// Provenance for a filesystem argument, including the directory that
/// anchored a relative operand.
pub(crate) fn fs_arg_node(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    index: u32,
    word: &Word,
) -> ProvenanceRef {
    let mut antecedents = ctx.arg_antecedents(index);
    if crate::paths::fs_word_uses_cwd(word) {
        antecedents.extend(ctx.cwd_node);
    }
    builder.node(ProvenanceKind::Argument { index }, &antecedents)
}

/// An effect on an explicit resource, attributed to one argv position and
/// the model application.
/// An effect on an explicit resource resolved from the operand at `index`. The
/// returned slot lets a transfer emitter pair the endpoint it just produced.
pub(crate) fn arg_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) -> Option<u32> {
    let arg = arg_node(builder, ctx, index);
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
        provenance: vec![arg, model_node],
    })
}

/// A filesystem effect on an explicit resource resolved from an operand. The
/// returned slot lets a transfer emitter pair the endpoint it just produced.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fs_arg_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operand: &Word,
    operation: &str,
    resource: ResourceExpr,
    attributes: Attrs,
) -> Option<u32> {
    let arg = fs_arg_node(builder, ctx, index, operand);
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
        provenance: vec![arg, model_node],
    })
}

/// One filesystem effect per operand word, resolved against cwd. The returned
/// slot lets a transfer emitter pair the endpoint it just produced.
pub(crate) fn operand_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operand: &Word,
    operation: &str,
    attributes: Attrs,
) -> Option<u32> {
    let arg = fs_arg_node(builder, ctx, index, operand);
    let mut resource = ctx.resolve_fs_word(operand);
    let provenance = vec![arg, model_node];
    if !follow_parent_links(builder, ctx, operand, &mut resource, &provenance) {
        return None;
    }
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
    })
}

/// A syntax-check mode reads a file operand without executing it.
pub(crate) fn syntax_check_operand(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
) {
    let Some(script) = ctx.argv.get(index) else {
        return;
    };
    if script.as_literal() == Some("-") {
        return;
    }
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    operand_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        script,
        "filesystem.read",
        BTreeMap::new(),
    );
}

pub(crate) fn code_execution(
    request_assurance: effinterp_proto::RequestAssurance,
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    argument: Option<u32>,
    source: &str,
    mut attributes: Attrs,
) {
    attributes.insert("source".to_string(), AttrValue::String(source.to_string()));
    let resource = code_execution_resource(ctx);
    let provenance = argument.map_or_else(
        || vec![model_node],
        |index| vec![arg_node(builder, ctx, index), model_node],
    );
    builder.effect(Effect {
        request_assurance,
        id: Default::default(),
        operation: Operation::new("process.code_execution"),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}

/// The interpreter process identity shared by every code-execution model.
pub(crate) fn code_execution_resource(ctx: &InvocationCtx) -> ResourceExpr {
    match ctx.argv.first().and_then(Word::as_literal) {
        Some(name) if !name.is_empty() => ResourceExpr::Concrete {
            identity: executable_identity(name, ctx.cwd),
        },
        _ => ResourceExpr::Unresolved {
            family: ResourceFamily::new("process"),
        },
    }
}

/// True when a word whose text is not recoverable still begins with one of an
/// interpreter's inline-source options (`python3 -c"$(curl …)"`). The code is
/// then an unrecoverable argument, never the script path operand it would
/// otherwise be mistaken for.
pub(crate) fn is_attached_inline_source(word: &Word, flags: &[&str]) -> bool {
    word.as_literal().is_none()
        && flags
            .iter()
            .any(|flag| word.literal_prefix().starts_with(flag))
}

pub(crate) fn dynamic_source(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    builder.boundary(Boundary {
        reason: BoundaryReason::DYNAMIC_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: ["environment", "filesystem", "network", "process"]
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

pub(crate) fn attrs(pairs: &[(&str, bool)]) -> Attrs {
    pairs
        .iter()
        .filter(|(_, on)| *on)
        .map(|(k, _)| (k.to_string(), AttrValue::Bool(true)))
        .collect()
}

/// Boundary for arguments the model did not recognize: a dashed token may
/// consume the next token in the real tool, so operand attribution beyond
/// this point is unreliable, and an extra operand is one the tool rejects or
/// the model does not run. The detail names each kind the way registry
/// models do.
pub(crate) fn unrecognized_arguments_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    domains: &[&str],
    unknown: &[(u32, String)],
) {
    if unknown.is_empty() {
        return;
    }
    let (flags, operands): (Vec<&str>, Vec<&str>) = unknown
        .iter()
        .map(|(_, name)| name.as_str())
        .partition(|name| name.starts_with('-'));
    let mut details = Vec::new();
    if !flags.is_empty() {
        details.push(format!("unrecognized flags: {}", flags.join(", ")));
    }
    if !operands.is_empty() {
        details.push(format!("unrecognized operands: {}", operands.join(", ")));
    }
    boundary(
        builder,
        model_node,
        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        BoundaryClass::Unmodeled,
        domains,
        &details.join("; "),
    );
}

/// Record a model-level gap without changing the model's coverage declarations.
pub(crate) fn boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    reason: BoundaryReason,
    class: BoundaryClass,
    domains: &[&str],
    detail: &str,
) {
    scoped_boundary(
        builder,
        model_node,
        reason,
        class,
        BoundaryScope::Invocation,
        domains,
        detail,
    );
}

/// Record what the environment does once the invocation runs, which the
/// model states in full as far as the invocation goes.
pub(crate) fn environment_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    reason: BoundaryReason,
    class: BoundaryClass,
    domains: &[&str],
    detail: &str,
) {
    scoped_boundary(
        builder,
        model_node,
        reason,
        class,
        BoundaryScope::Environment,
        domains,
        detail,
    );
}

fn scoped_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    reason: BoundaryReason,
    class: BoundaryClass,
    scope: BoundaryScope,
    domains: &[&str],
    detail: &str,
) {
    builder.boundary(Boundary {
        reason,
        class,
        scope,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

/// Unrecoverable executable source leaves both a dynamic-source gap and a source gap.
pub(crate) fn opaque_source(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    const DOMAINS: &[&str] = &["environment", "filesystem", "network", "process"];
    opaque_source_with_provenance(builder, &[model_node], DOMAINS, detail);
}

pub(crate) fn opaque_source_with_provenance(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    domains: &[&str],
    detail: &str,
) {
    for domain in domains {
        builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
    }
    for reason in [
        BoundaryReason::DYNAMIC_SOURCE,
        BoundaryReason::UNRECOVERABLE_SOURCE,
    ] {
        builder.boundary(Boundary {
            reason,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
            provenance: provenance.to_vec(),
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> WordPart {
        WordPart::Env(name.to_string())
    }

    fn literal(value: &str) -> WordPart {
        WordPart::Literal(value.to_string())
    }

    #[test]
    fn symbolic_expr_maps_word_parts_to_the_requested_family() {
        assert_eq!(
            symbolic_expr(
                &Word::new(vec![
                    literal("ssh://"),
                    env("HOST"),
                    WordPart::Glob("*".into()),
                    WordPart::Union(vec![Word::literal("a"), Word::literal("b")]),
                    WordPart::Unknown,
                ]),
                "network",
            ),
            ResourceExpr::Join {
                parts: vec![
                    ResourceExpr::Literal {
                        value: "ssh://".into(),
                    },
                    ResourceExpr::Environment {
                        name: "HOST".into(),
                    },
                    ResourceExpr::Unresolved {
                        family: ResourceFamily::new("network"),
                    },
                    ResourceExpr::Unresolved {
                        family: ResourceFamily::new("network"),
                    },
                    ResourceExpr::Unresolved {
                        family: ResourceFamily::new("network"),
                    },
                ],
            }
        );
        assert_eq!(
            symbolic_expr(&Word::new(vec![env("DEST")]), "cloud"),
            ResourceExpr::Environment {
                name: "DEST".into(),
            }
        );
    }

    #[test]
    fn leading_symbolic_without_distinguishes_ambiguous_and_local_shapes() {
        for word in [
            Word::new(vec![env("DEST")]),
            Word::new(vec![env("A"), env("B")]),
            Word::new(vec![WordPart::Unknown]),
            Word::new(vec![env("DEST"), literal("-bak")]),
        ] {
            assert!(leading_symbolic_without(&word, &[':', '/']));
        }
        for word in [
            Word::new(vec![literal("backup-"), env("DATE")]),
            Word::new(vec![env("HOME"), literal("/x")]),
            Word::new(vec![literal("./d/"), env("N")]),
        ] {
            assert!(!leading_symbolic_without(&word, &[':', '/']));
        }
    }
}
