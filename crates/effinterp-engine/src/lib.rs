//! The invocation engine: bounded static analysis of exec and shell subjects
//! into effinterp-proto effect plans. Pure with respect to the host: it never touches
//! the filesystem or environment; host facts arrive through the subject (cwd),
//! the caller-supplied [`SourceResolver`], and the [`ObservationResolver`] the
//! engine may question within its observation budget.
// Deadlines, lazily built model catalogs, cancellation flags, and thread-local
// budget meters are part of the engine's bounded-analysis contract. Host I/O
// methods remain forbidden.
#![allow(clippy::disallowed_macros, clippy::disallowed_types)]

mod builder;
mod control_flow;
mod dependency_calls;
mod exec;
mod external;
mod flow;
mod guards;
mod ir;
mod js;
mod lang;
mod limits;
mod models;
mod module_summary;
mod nest;
pub mod operand;
mod paths;
mod permission_mode;
pub use paths::SourcePattern;
pub use shell::shell_rubylib_paths;
mod python;
mod registration;
mod resource_transfer;
mod shell;
mod sql;
mod summary;
mod toolcall;
mod value;
mod word;

use std::collections::BTreeMap;

pub use builder::PlanBuilder;
pub use control_flow::{CallContract, ControlFact, ControlFlow, Exn, Requirements, Symbol};
pub use exec::{PATH_SEARCH_MODEL, UNRESOLVED_IDENTITY_MODEL};
pub use external::{
    ALL_DOMAINS, Domains, ExternalCall, canonical_rust_std_type, classify_go_call,
    classify_java_call, classify_python_call, classify_ruby_require, classify_rust_call,
    rust_inert_receiver_method,
};
pub use ir::{Assurance, ScopeKey, TypeRef, ValueOrigin};
pub use js::{js_external_effects, js_runs_module_scope_call};
pub use lang::go::go_external_effects;
pub use lang::ruby::{ruby_package_metadata, ruby_runs_top_level};
pub use lang::{RUST_DEFERRED_COMMAND, rust_is_entry_macro_line, scope_rust_branch_groups};
pub use limits::{AnalysisLimits, LimitsError};
pub use limits::{InvocationDeadline, SummaryBudget};
pub use models::pkgmgr::{PACKAGE_BINARY_INFERENCE_MODEL, PACKAGE_LAUNCH_MODELS};
pub use models::{
    Catalog, FrameworkLifecycle, GITHUB_ACTIONS_DRIVER, LIFECYCLE_CATALOG, LifecycleSig,
    RegistryError, compile_registry, compile_registry_with_builtin,
};
// Model-document types named through the engine by crates that do not depend on
// effinterp-model-schema, which owns them.
pub use effinterp_model_schema::{DeclarationDocument, SigEvidence, SigRole};
pub(crate) use module_summary::Linkage;
pub use module_summary::{
    CallEdge, CallResult, CallableVisibility, ClassEntry, DecoratorShape, DispatchContract,
    DispatchSignature, DispatchStyle, FunctionEntry, ImportBinding, Lang, ModuleLoadKind,
    ModuleSummary, module_summaries,
};
pub use python::{python_external_method_effects, python_plugin_path_pattern};
pub use registration::{Registration, RegistrationKind, registrations};
pub use resource_transfer::TransferBinding;
pub(crate) use summary::replay_transfers;
pub use summary::{Summary, substitute_resource_expr};
pub use value::{
    CallableValue, Cardinality, ObjectIdentity, ObjectValue, ResolvedObject, SemanticValue,
    SemanticValueKind, ValueArgument, ValueLimits, WidenReason, contains_callable, join_branches,
    lower_effect_value, merge_arguments, positional_arguments, property_access, substitute_value,
};
pub(crate) use value::{bind_arguments, substitute_value_counted};
pub use word::Word;

use std::cell::RefCell;
use std::sync::{Arc, atomic::AtomicBool};

use effinterp_proto::{Limits, Plan, Subject, ValidationError};

use nest::{Nest, analyze_subject};

/// Typed analysis failure: no plan could be constructed at all. Partial
/// understanding is not a failure; it is a plan with boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    Cancelled,
    EmptyArgv,
    InvalidPlan(Vec<ValidationError>),
    InvalidModels(String),
    InvalidSubject(effinterp_proto::SubjectValidationError),
    /// The caller's limits map was missing a known name or carried an unknown
    /// one. The engine never substitutes a default for a missing bound.
    InvalidLimits(LimitsError),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "analysis cancelled"),
            Self::EmptyArgv => write!(f, "exec subject has an empty argv"),
            Self::InvalidPlan(errors) => write!(
                f,
                "engine produced an invalid plan: {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::InvalidModels(error) => write!(f, "{error}"),
            Self::InvalidSubject(error) => write!(f, "invalid subject: {error}"),
            Self::InvalidLimits(error) => write!(f, "{error}"),
        }
    }
}

/// Why the engine is requesting source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePurpose {
    /// Source named directly by an analyzed invocation.
    InvocationInput,
    /// Executable file selected by command, hook, wrapper, or tool lookup.
    ExecutableInput,
    /// Source discovered transitively from another source file.
    DependencySource,
}

/// The path namespace that the caller must resolve against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceNamespace {
    /// A path in the caller's host filesystem view.
    Host,
    /// A path in an indexed repository view.
    Repository,
}

/// One typed request for source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRequest<'a> {
    /// Lexically normalized path in `namespace`.
    pub path: &'a str,
    /// Namespace in which `path` is meaningful.
    pub namespace: SourceNamespace,
    /// Whether the source was directly invoked or discovered transitively.
    pub purpose: SourcePurpose,
    /// Language of the source making this request, when it has one.
    pub requester_language: Option<&'a str>,
}

/// A stable reason that requested source is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// The requested path does not exist.
    Missing,
    /// Canonical resolution left the resolver's root.
    Escapes,
    /// The requested path does not identify a regular file.
    NotAFile,
    /// Resolver policy forbids dependency traversal.
    DependencyDenied,
    /// Resolver policy cannot map the requested namespace.
    NamespaceDenied,
    Stale,
    Mismatched,
    Ambiguous,
}

impl UnavailableReason {
    /// Stable snake-case representation used in boundary evidence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Escapes => "escapes",
            Self::NotAFile => "not_a_file",
            Self::DependencyDenied => "dependency_denied",
            Self::NamespaceDenied => "namespace_denied",
            Self::Stale => "stale",
            Self::Mismatched => "mismatched",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// A typed refusal to provide requested source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRefusal {
    /// The source is unavailable under the resolver's policy.
    Unavailable(UnavailableReason),
    /// Resolving the source would exceed a named limit.
    Limit { limit: &'static str },
}

/// The complete response contract for a source request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceResponse {
    /// Exact file bytes; UTF-8 validation remains the engine's responsibility.
    Source(Vec<u8>),
    /// A typed refusal with no source bytes.
    Refused(SourceRefusal),
}

/// What one analysis may still spend, handed to the host with every request
/// so it can refuse rather than overrun a bound the engine owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationBudget {
    /// Distinct external observations this analysis may still demand.
    pub remaining_requests: u64,
    /// Accounted bytes this analysis may still retain.
    pub remaining_bytes: u64,
    /// Whether the caller's deadline has already expired. A cooperative
    /// bound: a synchronous host call can still overrun it.
    pub expired: bool,
}

/// Supplies bounded facts about initial host state without letting the engine
/// touch the filesystem itself. Answers are metadata only; file bytes stay on
/// [`SourceResolver`]. The engine treats a resolver as an evidence authority:
/// it records exactly what was claimed and validates the answer's shape, and
/// a well-formed lie is not detectable here.
pub trait ObservationResolver: Send + Sync {
    /// Answer one typed request, or refuse it with a typed reason. A refusal
    /// is never proof of absence; `PathKind::Missing` is the fact that says so.
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        budget: ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome;
}

/// Supplies source bytes without letting the engine access files itself.
pub trait SourceResolver: Send + Sync {
    /// Return all matching files; None means the bounded inventory is unavailable.
    fn matching(&self, _pattern: &SourcePattern) -> Option<Vec<String>> {
        None
    }
    /// Return exact bytes or a stable refusal for one typed source request.
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse;
    /// Prove a lexically disjoint mutation cannot alias this source or its
    /// ancestors. Live resolvers must account for filesystem identity; absent
    /// observations are not proof. Alias-free virtual namespaces may return true.
    fn source_mutation_disjoint(
        &self,
        _resource: &effinterp_proto::ResourceExpr,
        _request: SourceRequest<'_>,
    ) -> bool {
        false
    }
    /// List same-directory source candidates, or `None` when closure is unavailable.
    fn siblings(&self, path: &str) -> Option<Vec<String>>;
    /// Prove that a demanded module stem has no native-extension candidates.
    /// True requires a complete bounded directory observation, including unindexed
    /// files and tagged suffixes. Missing observation is not proof of absence.
    fn python_native_candidates_absent(&self, _request: SourceRequest<'_>) -> bool {
        false
    }
    /// Exact ordered CPython extension suffixes for this launch.
    /// None means the compatible-build suffix list is unobserved.
    /// Tagged SOABI suffixes differ per build and stay resolver-supplied evidence;
    /// production host and repository resolvers return None rather than guessing.
    fn python_extension_suffixes(
        &self,
        _executable: &str,
        _cwd: Option<&str>,
    ) -> Option<Vec<String>> {
        None
    }
}

/// The invocation analysis engine: turns one subject into a validated effect plan
/// using its model catalog, analysis limits and optional source resolver.
pub struct Engine {
    causality_detail: bool,
    catalog: Arc<Catalog>,
    limits: AnalysisLimits,
    resolver: Option<Box<dyn SourceResolver>>,
    cancel: Option<Arc<AtomicBool>>,
}

/// What one analysis actually spent from the deterministic budget: counted
/// work units and accounted retained bytes, both platform-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnalysisStats {
    pub steps: u64,
    pub retained_bytes: u64,
    /// Binding entries walked while comparing, joining, or restoring whole
    /// binding environments. Not a budget: it shows whether that work stays
    /// proportional to the bindings a scope actually changes.
    pub state_scan_entries: u64,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            catalog: Catalog::shared_builtin(),
            limits: AnalysisLimits::default(),
            resolver: None,
            cancel: None,
            causality_detail: false,
        }
    }

    /// Build an engine from a protocol limits map. Every known limit name must
    /// be present and no unknown name may appear.
    pub fn with_limits(limits: Limits) -> Result<Self, EngineError> {
        Ok(Self {
            catalog: Catalog::shared_builtin(),
            limits: AnalysisLimits::from_map(&limits).map_err(EngineError::InvalidLimits)?,
            resolver: None,
            cancel: None,
            causality_detail: false,
        })
    }

    /// Load promoted documents on top of builtin models, rejecting conflicting owners.
    pub fn with_documents(sources: &[&str], limits: Limits) -> Result<Self, EngineError> {
        let registry = compile_registry_with_builtin(sources)
            .map_err(|error| EngineError::InvalidModels(error.to_string()))?;
        let catalog = Catalog::from_registry(registry)
            .map_err(|error| EngineError::InvalidModels(error.to_string()))?;
        Ok(Self {
            catalog: Arc::new(catalog),
            limits: AnalysisLimits::from_map(&limits).map_err(EngineError::InvalidLimits)?,
            resolver: None,
            cancel: None,
            causality_detail: false,
        })
    }

    pub fn with_catalog(catalog: Catalog) -> Self {
        Self {
            catalog: Arc::new(catalog),
            limits: AnalysisLimits::default(),
            resolver: None,
            cancel: None,
            causality_detail: false,
        }
    }

    /// Interrupt analysis at its next budget charge; cancellation returns no plan.
    pub fn with_cancel_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancel = Some(flag);
        self
    }

    pub fn with_resolver(mut self, resolver: Box<dyn SourceResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Effective deterministic limits used for this engine's analyses.
    pub fn limits(&self) -> &AnalysisLimits {
        &self.limits
    }

    /// Publish causal graph detail after full analysis and validation.
    pub fn with_causality_detail(mut self, enabled: bool) -> Self {
        self.causality_detail = enabled;
        self
    }

    pub fn analyze(&self, subject: &Subject) -> Result<Plan, EngineError> {
        let (source_cwd, runtime_cwd) = subject_cwds(subject);
        self.analyze_with_cwds(subject, source_cwd, runtime_cwd)
    }

    /// Use this resolver for this call, overriding any engine-owned resolver.
    pub fn analyze_with_resolver(
        &self,
        subject: &Subject,
        resolver: &dyn SourceResolver,
    ) -> Result<Plan, EngineError> {
        self.analyze_with_resolver_stats(subject, resolver)
            .map(|(plan, _)| plan)
    }

    /// Use a per-call resolver and report deterministic budget consumption.
    pub fn analyze_with_resolver_stats(
        &self,
        subject: &Subject,
        resolver: &dyn SourceResolver,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        let (source_cwd, runtime_cwd) = subject_cwds(subject);
        self.analyze_inner(
            subject,
            source_cwd,
            runtime_cwd,
            Some(resolver),
            None,
            None,
            None,
        )
    }

    /// Analyze and report what the run spent from the deterministic budget.
    /// `analyze` is this without the accounting.
    pub fn analyze_with_stats(
        &self,
        subject: &Subject,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        let (source_cwd, runtime_cwd) = subject_cwds(subject);
        self.analyze_cwds_with_stats(subject, source_cwd, runtime_cwd)
    }

    /// Analyze with an explicit repository source namespace. An empty value
    /// is repository root; None keeps relative launched-source paths opaque.
    pub fn analyze_with_source_cwd(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
    ) -> Result<Plan, EngineError> {
        self.analyze_with_cwds(subject, source_cwd, source_cwd)
    }

    /// Analyze with distinct repository namespaces for the source file and
    /// the process runtime cwd.
    pub fn analyze_with_cwds(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
        runtime_cwd: Option<&str>,
    ) -> Result<Plan, EngineError> {
        self.analyze_cwds_with_stats(subject, source_cwd, runtime_cwd)
            .map(|(plan, _)| plan)
    }

    /// Analyze with distinct repository namespaces and report deterministic
    /// budget consumption.
    pub fn analyze_cwds_with_stats(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
        runtime_cwd: Option<&str>,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        self.analyze_inner(
            subject,
            source_cwd,
            runtime_cwd,
            self.resolver.as_deref(),
            None,
            None,
            None,
        )
    }

    /// Analyze a file entrypoint with its repository or host source origin.
    pub fn analyze_file_cwds_with_stats(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
        runtime_cwd: Option<&str>,
        origin: Option<&str>,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        self.analyze_inner(
            subject,
            source_cwd,
            runtime_cwd,
            self.resolver.as_deref(),
            origin,
            None,
            None,
        )
    }

    /// Repository declaration analysis executes initialization; composition enters
    /// the evidence's selected handlers using the normal module summaries.
    pub fn analyze_registration_initialization(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
        registration: &Registration,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        self.analyze_inner(
            subject,
            source_cwd,
            None,
            self.resolver.as_deref(),
            Some(&registration.file),
            None,
            Some(registration),
        )
    }

    /// Analyze under one caller-owned deadline, including all source observations.
    /// A per-call resolver overrides the engine resolver; expiration returns a
    /// validated partial plan, while explicit cancellation remains an error.
    pub fn analyze_with_deadline(
        &self,
        subject: &Subject,
        deadline: &InvocationDeadline,
        resolver: Option<&dyn SourceResolver>,
    ) -> Result<Plan, EngineError> {
        let (source_cwd, runtime_cwd) = subject_cwds(subject);
        self.analyze_inner(
            subject,
            source_cwd,
            runtime_cwd,
            resolver.or(self.resolver.as_deref()),
            None,
            Some(deadline),
            None,
        )
        .map(|(plan, _)| plan)
    }

    /// Analyze with both host channels: source bytes and lazy observations of
    /// initial host state. Either may be absent; without an observation
    /// resolver the engine demands no facts and emits no observation-backed
    /// conclusion, so the plan is the one the byte-only entry points produce.
    pub fn analyze_with_observations(
        &self,
        subject: &Subject,
        deadline: Option<&InvocationDeadline>,
        sources: Option<&dyn SourceResolver>,
        observations: Option<Arc<dyn ObservationResolver>>,
    ) -> Result<Plan, EngineError> {
        let (source_cwd, runtime_cwd) = subject_cwds(subject);
        self.analyze_observed(
            subject,
            source_cwd,
            runtime_cwd,
            sources.or(self.resolver.as_deref()),
            None,
            deadline,
            None,
            observations,
        )
        .map(|(plan, _)| plan)
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_inner(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
        runtime_cwd: Option<&str>,
        resolver: Option<&dyn SourceResolver>,
        source_origin: Option<&str>,
        deadline: Option<&InvocationDeadline>,
        registration: Option<&Registration>,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        self.analyze_observed(
            subject,
            source_cwd,
            runtime_cwd,
            resolver,
            source_origin,
            deadline,
            registration,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_observed(
        &self,
        subject: &Subject,
        source_cwd: Option<&str>,
        runtime_cwd: Option<&str>,
        resolver: Option<&dyn SourceResolver>,
        source_origin: Option<&str>,
        deadline: Option<&InvocationDeadline>,
        registration: Option<&Registration>,
        observations: Option<Arc<dyn ObservationResolver>>,
    ) -> Result<(Plan, AnalysisStats), EngineError> {
        if let Subject::Exec { argv, .. } = subject
            && argv.is_empty()
        {
            return Err(EngineError::EmptyArgv);
        }
        effinterp_proto::validate_subject(subject).map_err(EngineError::InvalidSubject)?;
        let mut builder = PlanBuilder::new(
            subject.clone(),
            engine_version(),
            self.catalog.model_set_id(),
            self.limits.clone(),
        );
        if let Some(registration) = registration {
            let provenance: Vec<_> = registration
                .spans
                .iter()
                .map(|(start, end)| {
                    builder.node(
                        effinterp_proto::ProvenanceKind::SourceSpan {
                            start: *start,
                            end: *end,
                        },
                        &[],
                    )
                })
                .collect();
            for unresolved in &registration.unresolved {
                builder.boundary(effinterp_proto::Boundary {
                    reason: if unresolved == "dynamic_registration" {
                        effinterp_proto::BoundaryReason::DYNAMIC_REGISTRATION
                    } else {
                        effinterp_proto::BoundaryReason::REGISTRATION_CONTEXT
                    },
                    class: effinterp_proto::BoundaryClass::Unresolved,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: builder::KNOWN_DOMAINS
                        .iter()
                        .map(|domain| effinterp_proto::Domain::new(*domain))
                        .collect(),
                    provenance: provenance.clone(),
                    limit: None,
                    detail: Some(unresolved.clone()),
                });
            }
        }
        builder.set_cancel_flag(self.cancel.clone());
        builder.set_deadline(deadline.cloned());
        let observed = observations.is_some();
        builder.set_observations(observations);
        if matches!(subject, Subject::Shell { .. } | Subject::Source { .. }) {
            builder.control_allow_roots();
        }
        let budget = builder.budget();
        let _condition_scope = guards::enter_budget(budget.clone());
        let nest = Nest {
            registration,
            path_platform: builder.path_platform(),
            script_origins: RefCell::new(vec![source_origin.map(str::to_string)]),
            current_script: RefCell::new(None),
            package_manifest: RefCell::new(None),
            catalog: &self.catalog,
            limits: &self.limits,
            budget: &budget,
            resolver,
            source_origin,
            context: match subject {
                Subject::Exec { context, .. }
                | Subject::Shell { context, .. }
                | Subject::Source { context, .. }
                | Subject::ToolCall { context, .. } => Some(context),
                Subject::Sql { .. } => None,
            },
            source_cwds: RefCell::new(vec![source_cwd.map(str::to_string)]),
            runtime_cwds: RefCell::new(vec![runtime_cwd.map(str::to_string)]),
            cwd_nodes: RefCell::new(vec![None]),
            mounts: RefCell::new(vec![Vec::new()]),
            environments: RefCell::new(vec![BTreeMap::new()]),
            environment_nodes: RefCell::new(vec![BTreeMap::new()]),
            environment_unsets: RefCell::new(vec![match subject {
                Subject::Exec { context, .. }
                | Subject::Shell { context, .. }
                | Subject::Source { context, .. }
                | Subject::ToolCall { context, .. } => context.env_unset.clone(),
                Subject::Sql { .. } => Default::default(),
            }]),
            environment_concealed: RefCell::new(vec![std::collections::BTreeSet::new()]),
            environment_closed: RefCell::new(vec![false]),
            source_resolution_disabled: Default::default(),
            selected_source_inputs: RefCell::new(Default::default()),
            resolved_invocation_sources: RefCell::new(Default::default()),
            shell_arguments: RefCell::new(None),
            physical_cwd: Default::default(),
            python_import_search: RefCell::new(None),
            python_imports: Default::default(),
            dependency_calls: Default::default(),
        };
        analyze_subject(&mut builder, &nest, subject, None, None, 0);
        if budget.cancelled()
            || self
                .cancel
                .as_ref()
                .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
        {
            return Err(EngineError::Cancelled);
        }
        if budget.timed_out() {
            builder.note_deadline();
        }
        budget.begin_finalization();
        let mut plan = builder.finish().map_err(EngineError::InvalidPlan)?;
        // Source alternatives cannot be enumerated without a resolver. Keep
        // resolver-free plans byte-stable rather than reporting an unused bound.
        if resolver.is_none() {
            plan.analysis.limits.remove("max_source_alternatives");
        }
        // The same rule for the observation channel: an analysis that could
        // not ask reports no bound it never drew on.
        if !observed {
            plan.analysis.limits.remove("max_observation_requests");
        }
        if !self.causality_detail {
            plan.causality.graph = None;
        }
        let stats = AnalysisStats {
            steps: budget.steps(),
            retained_bytes: budget.retained_bytes(),
            state_scan_entries: budget.state_scan_entries(),
        };
        Ok((plan, stats))
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// The source and runtime repository namespaces implied by a subject.
fn subject_cwds(subject: &Subject) -> (Option<&str>, Option<&str>) {
    match subject {
        Subject::Exec { cwd, .. } | Subject::Shell { cwd, .. } => {
            let cwd = Some(cwd.as_deref().unwrap_or(""));
            (cwd, cwd)
        }
        Subject::Source { cwd, .. } => (Some(cwd.as_deref().unwrap_or("")), cwd.as_deref()),
        Subject::ToolCall { cwd, .. } => (None, cwd.as_deref()),
        Subject::Sql { .. } => (None, None),
    }
}

/// The engine version stamped into every plan: the effinterp-engine package version.
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The protocol limits map every caller starts from: the typed defaults,
/// serialized. `AnalysisLimits::default()` is the single source of truth.
pub fn default_limits() -> Limits {
    AnalysisLimits::default().to_map()
}
