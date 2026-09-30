use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::effect::Effect;
use crate::execution::ExecutionGraph;
use crate::provenance::{ProvenanceNode, ProvenanceRef};
use crate::subject::Subject;

/// The canonical universe of effect domains. Every mechanism that reasons about
/// "all domains" — plan-builder opacity, cross-file composition widening,
/// validation, query classification — consumes this one list, so adding a
/// domain is a single edit rather than a hunt for copied string arrays.
pub const DOMAINS: [&str; 12] = [
    "artifact",
    "filesystem",
    "process",
    "environment",
    "network",
    "database",
    "container",
    "git",
    "cloud",
    "messaging",
    "system",
    "credential",
];

/// An effect domain such as "filesystem" or "process". Open-ended string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Domain(pub String);

impl Domain {
    pub fn new(domain: impl Into<String>) -> Self {
        Self(domain.into())
    }
}

/// What effect-relevant behavior the analyzer preserved in a domain. Not a
/// claim that arbitrary code was understood.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    /// Every possible effect is bounded; zero effects means none in scope.
    Full,
    /// Useful evidence remains, but the named gaps may hide additional effects.
    Partial,
    /// No usable completeness bound remains; retained effects are possibilities.
    None,
}

/// Coverage by effect domain. A plan must state coverage for every domain it
/// reports effects in; consumers must not infer completeness from an empty
/// effect list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Coverage(pub BTreeMap<Domain, CoverageClaim>);

/// A scoped conservative bound on possible effects, never an assertion of
/// occurrence. Full covers every possible effect in the domain under the
/// subject's execution scope, supplied context and applicable semantic models.
/// Partial/None retain exact boundary references explaining omitted behavior.
/// Scope follows the subject/root, including reachable callees, callbacks,
/// nested realms, and exceptional/cleanup paths, not just traversed paths.
/// Unsupplied input is not evidence of absence. This evidence is not permission.
/// Plans use positional BoundaryRef; repository answers can use stable string IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "R: Deserialize<'de>"))]
pub struct CoverageClaim<R = BoundaryRef> {
    pub level: CoverageLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<R>,
}

impl Coverage {
    pub fn level(&self, domain: &Domain) -> Option<CoverageLevel> {
        self.0.get(domain).map(|claim| claim.level)
    }

    pub fn is_full(&self, domain: &Domain) -> bool {
        self.level(domain) == Some(CoverageLevel::Full)
    }

    /// Empty requirements make no completeness claim. Duplicate domains do
    /// not change the result; absence never implies Full.
    pub fn covers_fully<'a>(&self, required: impl IntoIterator<Item = &'a Domain>) -> bool {
        let mut required = required.into_iter().peekable();
        required.peek().is_some() && required.all(|domain| self.is_full(domain))
    }

    pub fn gaps(&self, domain: &Domain) -> &[BoundaryRef] {
        self.0
            .get(domain)
            .map_or(&[], |claim| claim.gaps.as_slice())
    }
}

/// Configured analysis limits, keyed by a stable limit name. Saturation is
/// reported as a boundary referencing the limit name.
pub type Limits = BTreeMap<String, u64>;

/// Whether an analysis completed or stopped at a hard execution boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AnalysisOutcome {
    #[default]
    Complete,
    Refused {
        kind: AnalysisRefusalKind,
    },
}

impl AnalysisOutcome {
    fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Machine-readable hard analysis refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisRefusalKind {
    DeadlineExceeded,
}

/// Identity of the analysis that produced a plan. The same subject, engine,
/// model set, and limits must produce byte-identical canonical plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    pub engine_version: String,
    /// Content identity of the model set used.
    pub model_set: String,
    pub limits: Limits,
    #[serde(default, skip_serializing_if = "AnalysisOutcome::is_complete")]
    pub outcome: AnalysisOutcome,
}

/// Index into a plan's `boundaries` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BoundaryRef(pub u32);

/// Stable machine-readable reason code. The wire vocabulary remains open, but
/// codes are canonical lower snake case and internal emitters use the named
/// values below.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundaryReason(Cow<'static, str>);

impl BoundaryReason {
    pub const BRANCH_STARVED: Self = Self(Cow::Borrowed("branch_starved"));
    pub const CHROOT_REROOTS_FILESYSTEM: Self = Self(Cow::Borrowed("chroot_reroots_filesystem"));
    pub const CLUSTER_API: Self = Self(Cow::Borrowed("cluster_api"));
    pub const CROSS_MODULE: Self = Self(Cow::Borrowed("cross_module"));
    pub const DISPATCH_ROUNDS_EXHAUSTED: Self = Self(Cow::Borrowed("dispatch_rounds_exhausted"));
    pub const DYNAMIC_CALL: Self = Self(Cow::Borrowed("dynamic_call"));
    pub const DYNAMIC_CLASS: Self = Self(Cow::Borrowed("dynamic_class"));
    pub const DYNAMIC_DISPATCH: Self = Self(Cow::Borrowed("dynamic_dispatch"));
    pub const DYNAMIC_INCLUDE: Self = Self(Cow::Borrowed("dynamic_include"));
    pub const DYNAMIC_REGISTRATION: Self = Self(Cow::Borrowed("dynamic_registration"));
    pub const DYNAMIC_SOURCE: Self = Self(Cow::Borrowed("dynamic_source"));
    pub const EXECUTION_CYCLE: Self = Self(Cow::Borrowed("execution_cycle"));
    pub const EXECUTION_LIMIT: Self = Self(Cow::Borrowed("execution_limit"));
    pub const EXTERNAL_INERT: Self = Self(Cow::Borrowed("external_inert"));
    pub const EXTERNAL_MODELED: Self = Self(Cow::Borrowed("external_modeled"));
    pub const EXTERNAL_UNMODELED: Self = Self(Cow::Borrowed("external_unmodeled"));
    pub const FRONTEND_PARTIAL: Self = Self(Cow::Borrowed("frontend_partial"));
    pub const PARSE_ERROR: Self = Self(Cow::Borrowed("parse_error"));
    pub const INPUT_DETERMINED_ARGUMENTS: Self = Self(Cow::Borrowed("input_determined_arguments"));
    pub const INCLUDE_CYCLE: Self = Self(Cow::Borrowed("include_cycle"));
    pub const INTERACTIVE_INPUT: Self = Self(Cow::Borrowed("interactive_input"));
    pub const LAUNCH_CYCLE: Self = Self(Cow::Borrowed("launch_cycle"));
    pub const LIFECYCLE_UNBOUND: Self = Self(Cow::Borrowed("lifecycle_unbound"));
    pub const LIMIT_SATURATED: Self = Self(Cow::Borrowed("limit_saturated"));
    pub const PATCH_PARSE_FAILURE: Self = Self(Cow::Borrowed("patch_parse_failure"));
    pub const MISSING_REQUIRED_ARGUMENTS: Self = Self(Cow::Borrowed("missing_required_arguments"));
    pub const MUTUALLY_EXCLUSIVE_ARGUMENTS: Self =
        Self(Cow::Borrowed("mutually_exclusive_arguments"));
    pub const MODEL_COVERAGE: Self = Self(Cow::Borrowed("model_coverage"));
    pub const NO_ENTRY_POINT: Self = Self(Cow::Borrowed("no_entry_point"));
    pub const OBSERVATION_UNAVAILABLE: Self = Self(Cow::Borrowed("observation_unavailable"));
    pub const PACKAGE_SCRIPTS: Self = Self(Cow::Borrowed("package_scripts"));
    pub const PARTIAL_ANALYSIS: Self = Self(Cow::Borrowed("partial_analysis"));
    /// The daemon's transport and connection behavior depend on the runtime environment.
    pub const DAEMON_TRANSPORT: Self = Self(Cow::Borrowed("daemon_transport"));
    /// Providers and state backends may execute code or perform I/O beyond the invocation.
    pub const PROVIDER_IO: Self = Self(Cow::Borrowed("provider_io"));
    /// Runtime-managed identities, contents, or paths require live inventory.
    pub const LIVE_INVENTORY: Self = Self(Cow::Borrowed("live_inventory"));
    /// Additional configuration, authentication, and transport behavior depends on the environment.
    pub const ENVIRONMENT_CONFIGURATION: Self = Self(Cow::Borrowed("environment_configuration"));
    /// A reviewed invocation surface leaves environmental behavior outside the model.
    pub const REVIEWED_COMMAND_SURFACE: Self = Self(Cow::Borrowed("reviewed_command_surface"));
    pub const REEXPORT_AMBIGUOUS: Self = Self(Cow::Borrowed("reexport_ambiguous"));
    pub const REEXPORT_CYCLE: Self = Self(Cow::Borrowed("reexport_cycle"));
    pub const REEXPORT_LIMIT: Self = Self(Cow::Borrowed("reexport_limit"));
    pub const RECURSIVE_CALL: Self = Self(Cow::Borrowed("recursive_call"));
    pub const REMOTE_COMMAND: Self = Self(Cow::Borrowed("remote_command"));
    pub const TYPE_NARROWING: Self = Self(Cow::Borrowed("type_narrowing"));
    pub const UNPOLLED_ASYNC: Self = Self(Cow::Borrowed("unpolled_async"));
    pub const UNCOMPOSED_QUERY: Self = Self(Cow::Borrowed("uncomposed_query"));
    pub const UNCOMPOSED_SQL: Self = Self(Cow::Borrowed("uncomposed_sql"));
    pub const UNCOMPOSED_SUBPROCESS: Self = Self(Cow::Borrowed("uncomposed_subprocess"));
    pub const UNEXPANDED_MACRO: Self = Self(Cow::Borrowed("unexpanded_macro"));
    pub const UNMODELED_COMMAND: Self = Self(Cow::Borrowed("unmodeled_command"));
    pub const UNMODELED_ARCHIVE_OUTPUT: Self = Self(Cow::Borrowed("unmodeled_archive_output"));
    pub const UNMODELED_DYNAMIC: Self = Self(Cow::Borrowed("unmodeled_dynamic"));
    pub const UNMODELED_DYNAMIC_CODE: Self = Self(Cow::Borrowed("unmodeled_dynamic_code"));
    pub const UNMODELED_HOOKS: Self = Self(Cow::Borrowed("unmodeled_hooks"));
    pub const UNMODELED_INLINE_CODE: Self = Self(Cow::Borrowed("unmodeled_inline_code"));
    pub const UNMODELED_IMPORT: Self = Self(Cow::Borrowed("unmodeled_import"));
    pub const UNMODELED_SUBCOMMAND: Self = Self(Cow::Borrowed("unmodeled_subcommand"));
    pub const UNMODELED_SUBPROCESS: Self = Self(Cow::Borrowed("unmodeled_subprocess"));
    pub const UNPARSED_PARTITION_OPS: Self = Self(Cow::Borrowed("unparsed_partition_ops"));
    pub const UNPARSED_SCRIPT: Self = Self(Cow::Borrowed("unparsed_script"));
    pub const UNREAD_CONFIG: Self = Self(Cow::Borrowed("unread_config"));
    pub const UNRECOGNIZED_ARGUMENTS: Self = Self(Cow::Borrowed("unrecognized_arguments"));
    pub const UNSUPPORTED_SOURCE: Self = Self(Cow::Borrowed("unsupported_source"));
    pub const UNRECOVERABLE_SOURCE: Self = Self(Cow::Borrowed("unrecoverable_source"));
    pub const UNRESOLVED_ALIAS: Self = Self(Cow::Borrowed("unresolved_alias"));
    pub const UNRESOLVED_BUILD_TARGET: Self = Self(Cow::Borrowed("unresolved_build_target"));
    pub const UNRESOLVED_CALL: Self = Self(Cow::Borrowed("unresolved_call"));
    pub const UNRESOLVED_COMMAND: Self = Self(Cow::Borrowed("unresolved_command"));
    pub const UNRESOLVED_CI_STEP: Self = Self(Cow::Borrowed("unresolved_ci_step"));
    pub const UNRESOLVED_DECORATOR: Self = Self(Cow::Borrowed("unresolved_decorator"));
    pub const UNRESOLVED_INTERFACE: Self = Self(Cow::Borrowed("unresolved_interface"));
    pub const UNRESOLVED_INCLUDE: Self = Self(Cow::Borrowed("unresolved_include"));
    pub const UNRESOLVED_PACKAGE_SCRIPT: Self = Self(Cow::Borrowed("unresolved_package_script"));
    pub const UNRESOLVED_SOURCE: Self = Self(Cow::Borrowed("unresolved_source"));
    pub const UNRESOLVED_SQL: Self = Self(Cow::Borrowed("unresolved_sql"));
    pub const UNRESOLVED_TRANSFER_TARGET: Self = Self(Cow::Borrowed("unresolved_transfer_target"));
    pub const UNRESOLVED_TOOL_PATH: Self = Self(Cow::Borrowed("unresolved_tool_path"));
    pub const UNRESOLVED_TRAP_ACTION: Self = Self(Cow::Borrowed("unresolved_trap_action"));
    pub const UNSUPPORTED_SQL: Self = Self(Cow::Borrowed("unsupported_sql"));
    pub const UNSUPPORTED_SHELL_SYNTAX: Self = Self(Cow::Borrowed("unsupported_shell_syntax"));
    pub const UNSUPPORTED_TOOL: Self = Self(Cow::Borrowed("unsupported_tool"));
    pub const UNTYPED_RESOURCE: Self = Self(Cow::Borrowed("untyped_resource"));
    pub const ESCAPED_CALLABLE: Self = Self(Cow::Borrowed("escaped_callable"));
    pub const KUBERNETES_TARGET_API: Self = Self(Cow::Borrowed("kubernetes_target_api"));
    pub const REGISTRATION_CONTEXT: Self = Self(Cow::Borrowed("registration_context"));
    pub const UNKNOWN_IPYTHON_MAGIC: Self = Self(Cow::Borrowed("unknown_ipython_magic"));
    pub const VALUE_WIDENED: Self = Self(Cow::Borrowed("value_widened"));

    pub fn new(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        assert!(
            Self::is_valid_code(&reason),
            "invalid boundary reason {reason:?}"
        );
        Self(Cow::Owned(reason))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn spec(&self) -> Option<&'static BoundaryReasonSpec> {
        Self::registered(self.as_str())
    }

    pub fn registered(reason: &str) -> Option<&'static BoundaryReasonSpec> {
        BOUNDARY_REASONS.iter().find(|spec| spec.reason == reason)
    }

    pub fn is_valid(&self) -> bool {
        Self::is_valid_code(self.as_str())
    }

    pub fn is_valid_code(reason: &str) -> bool {
        reason
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase())
            && reason.split('_').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
    }
}

impl fmt::Display for BoundaryReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<str> for BoundaryReason {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for BoundaryReason {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Serialize for BoundaryReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BoundaryReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Cow::Owned(String::deserialize(deserializer)?)))
    }
}

/// A registered boundary reason. Environment scope is a claim that the
/// boundary is behavior the environment adds once the invocation runs, so only
/// reasons that name such behavior may carry it.
#[derive(Debug)]
pub struct BoundaryReasonSpec {
    pub reason: BoundaryReason,
    pub environment: bool,
}

/// The registered writer vocabulary: every reason the engine and its shipped
/// models emit. Readers may retain reasons outside this registry.
pub const BOUNDARY_REASONS: &[BoundaryReasonSpec] = &[
    BoundaryReasonSpec {
        reason: BoundaryReason::BRANCH_STARVED,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::CHROOT_REROOTS_FILESYSTEM,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::CLUSTER_API,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::CROSS_MODULE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DAEMON_TRANSPORT,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DISPATCH_ROUNDS_EXHAUSTED,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DYNAMIC_CALL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DYNAMIC_CLASS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DYNAMIC_DISPATCH,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DYNAMIC_INCLUDE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DYNAMIC_REGISTRATION,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::DYNAMIC_SOURCE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::ESCAPED_CALLABLE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::EXECUTION_CYCLE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::EXECUTION_LIMIT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::EXTERNAL_INERT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::EXTERNAL_MODELED,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::EXTERNAL_UNMODELED,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::FRONTEND_PARTIAL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::INCLUDE_CYCLE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::INTERACTIVE_INPUT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::KUBERNETES_TARGET_API,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::LAUNCH_CYCLE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::LIFECYCLE_UNBOUND,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::LIMIT_SATURATED,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::LIVE_INVENTORY,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::MISSING_REQUIRED_ARGUMENTS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::MODEL_COVERAGE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::MUTUALLY_EXCLUSIVE_ARGUMENTS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::NO_ENTRY_POINT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::PACKAGE_SCRIPTS,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::PARSE_ERROR,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::PARTIAL_ANALYSIS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::PATCH_PARSE_FAILURE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::PROVIDER_IO,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::RECURSIVE_CALL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::REEXPORT_AMBIGUOUS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::REEXPORT_CYCLE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::REEXPORT_LIMIT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::REGISTRATION_CONTEXT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::REMOTE_COMMAND,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::REVIEWED_COMMAND_SURFACE,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::TYPE_NARROWING,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNCOMPOSED_QUERY,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNCOMPOSED_SQL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNEXPANDED_MACRO,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNKNOWN_IPYTHON_MAGIC,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_ARCHIVE_OUTPUT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_COMMAND,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_DYNAMIC,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_DYNAMIC_CODE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_HOOKS,
        environment: true,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_IMPORT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_INLINE_CODE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_SUBCOMMAND,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNMODELED_SUBPROCESS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNPARSED_PARTITION_OPS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNPARSED_SCRIPT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNPOLLED_ASYNC,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNREAD_CONFIG,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_ALIAS,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_BUILD_TARGET,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_CALL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_CI_STEP,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_COMMAND,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_DECORATOR,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_INCLUDE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_INTERFACE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_PACKAGE_SCRIPT,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_SOURCE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_SQL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_TOOL_PATH,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_TRANSFER_TARGET,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNRESOLVED_TRAP_ACTION,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNSUPPORTED_SOURCE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNSUPPORTED_SQL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNSUPPORTED_TOOL,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::UNTYPED_RESOURCE,
        environment: false,
    },
    BoundaryReasonSpec {
        reason: BoundaryReason::VALUE_WIDENED,
        environment: false,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryClass {
    Unmodeled,
    Unresolved,
    Limit,
    ParseFailure,
    Unsupported,
}

impl fmt::Display for BoundaryClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unmodeled => "unmodeled",
            Self::Unresolved => "unresolved",
            Self::Limit => "limit",
            Self::ParseFailure => "parse_failure",
            Self::Unsupported => "unsupported",
        })
    }
}

/// Whether a boundary leaves the invocation itself incompletely understood,
/// or states what the environment does once the invocation runs: hooks,
/// package scripts, configured endpoints, live inventory. The emitter that
/// raises the boundary decides; validation admits environment scope only for
/// a registered environmental reason on an unmodeled or unresolved boundary
/// that no limit cut short.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryScope {
    #[default]
    Invocation,
    Environment,
}

impl BoundaryScope {
    pub fn is_invocation(&self) -> bool {
        *self == Self::Invocation
    }
}

/// The imported module and symbol named by an unresolved call boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CalleeReference {
    pub module: String,
    pub symbol: String,
}

/// A first-class record of analysis that could not continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    pub reason: BoundaryReason,
    pub class: BoundaryClass,
    #[serde(default, skip_serializing_if = "BoundaryScope::is_invocation")]
    pub scope: BoundaryScope,
    /// Effect domains whose coverage this boundary affects.
    pub domains: Vec<Domain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_resource: Option<crate::ResourceExpr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee: Option<CalleeReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
    /// The configured limit that saturated, when the reason is a limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The top-level analysis result: the unit consumers receive and validate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub schema: String,
    pub subject: Subject,
    pub analysis: Analysis,
    pub effects: Vec<Effect>,
    pub execution_graph: ExecutionGraph,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<Boundary>,
    pub coverage: Coverage,
    /// Causal coverage with optional occurrence-based graph detail.
    pub causality: crate::flow::Causality,
}

impl Plan {
    /// Derive effect IDs in one batch. Check references before indexing and hash
    /// each referenced subject once; duplicate groups span the entire plan.
    pub fn expected_effect_ids(&self) -> Result<Vec<crate::EffectId>, Vec<crate::ValidationError>> {
        let errors: Vec<_> = self
            .effects
            .iter()
            .enumerate()
            .filter(|(_, effect)| effect.execution.0 as usize >= self.execution_graph.nodes.len())
            .map(
                |(index, effect)| crate::ValidationError::DanglingExecutionRef {
                    context: format!("effects[{index}]"),
                    node: effect.execution.0,
                },
            )
            .collect();
        if !errors.is_empty() {
            return Err(errors);
        }
        let mut subjects = BTreeMap::new();
        let mut ordinals = BTreeMap::<String, u32>::new();
        Ok(self
            .effects
            .iter()
            .map(|effect| {
                let node = &self.execution_graph.nodes[effect.execution.0 as usize];
                let digest = subjects
                    .entry(effect.execution)
                    .or_insert_with(|| crate::canonical_hash(&node.subject));
                let mut identity = crate::EffectIdentity {
                    operation: effect.operation.clone(),
                    resource: crate::normalize_resource(
                        effect.resource.clone(),
                        crate::PathPlatform::Posix,
                    ),
                    realm: effect.realm.clone(),
                    modality: effect.modality,
                    request_assurance: effect.request_assurance,
                    attributes: effect.attributes.clone(),
                    condition: effect.condition.as_ref().map(crate::Condition::identity),
                    occurrence: crate::EffectOccurrence {
                        subject_digest: digest.clone(),
                        realm: node.realm.clone(),
                        ordinal: 0,
                    },
                };
                let key = serde_json::to_string(&identity).expect("effect identity serialization");
                let ordinal = ordinals.entry(key).or_default();
                identity.occurrence.ordinal = *ordinal;
                *ordinal += 1;
                crate::EffectId::derive(&identity)
            })
            .collect())
    }

    /// Reseal after effect or execution-subject edits, once ownership and order are final.
    pub fn stamp_effect_ids(&mut self) -> Result<(), Vec<crate::ValidationError>> {
        let ids = self.expected_effect_ids()?;
        for (effect, id) in self.effects.iter_mut().zip(ids) {
            effect.id = id;
        }
        Ok(())
    }
}
