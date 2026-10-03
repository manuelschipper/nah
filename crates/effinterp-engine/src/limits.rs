//! Typed analysis limits: the complete, closed set of bounds one analysis run
//! obeys, and the accounted-byte schedule the retained-bytes meter charges.
//!
//! The protocol carries limits as an open `name -> u64` map so a plan can be
//! read without the engine. The engine itself refuses that openness: an
//! unknown name is a caller typo and a missing name used to mean "unlimited",
//! so [`AnalysisLimits::from_map`] rejects both.

use effinterp_proto::{
    AttrValue, ContainerStorage, Effect, ExecutionNode, ExecutionRealm, Limits, ResourceExpr,
    ResourceIdentity,
};

/// Caller-owned monotonic invocation deadline. Clones share expiration, including
/// across host observations and resumed calls. No clock value enters a plan.
#[derive(Debug, Clone)]
pub struct InvocationDeadline {
    stop_at: std::time::Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The deadline this one was split from, whose expiry also ends this one.
    parent: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl InvocationDeadline {
    /// Reserve up to 10% (at most 10 ms) for validated plan finalization.
    /// Parsing and synchronous resolver calls may overrun this cooperative budget.
    pub fn after(duration: std::time::Duration) -> Self {
        let reserve = (duration / 10).min(std::time::Duration::from_millis(10));
        Self::at(std::time::Instant::now() + duration.saturating_sub(reserve))
    }

    /// Reuse an absolute monotonic work deadline chosen by the caller.
    pub fn at(stop_at: std::time::Instant) -> Self {
        Self {
            stop_at,
            expired: Default::default(),
            parent: None,
        }
    }

    /// A deadline at half the time this one has left, which also expires
    /// with it; expiring the half leaves this one running.
    pub fn half(&self) -> Self {
        let now = std::time::Instant::now();
        Self {
            stop_at: now + self.stop_at.saturating_duration_since(now) / 2,
            expired: Default::default(),
            parent: Some(self.expired.clone()),
        }
    }

    /// Stop scheduling work, for example when a host observation exhausts its budget.
    pub fn expire(&self) {
        self.expired
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn expired(&self) -> bool {
        if std::time::Instant::now() >= self.stop_at {
            self.expire();
        }
        self.expired.load(std::sync::atomic::Ordering::Relaxed)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// A limits map that cannot be turned into [`AnalysisLimits`]. Both cases are
/// caller mistakes: the engine never fills in a default for a name a caller
/// left out, because a silently unlimited bound is how pathological input
/// stalls a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitsError {
    /// A known limit name absent from the map.
    Missing(String),
    /// A name the engine does not know.
    Unknown(String),
}

impl std::fmt::Display for LimitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "missing limit {name}"),
            Self::Unknown(name) => write!(f, "unknown limit {name}"),
        }
    }
}

/// Declares every limit once: the field, its protocol name, and its default.
macro_rules! analysis_limits {
    ($($field:ident = $default:expr,)*) => {
        /// Every bound one analysis obeys, one `u64` field per protocol limit
        /// name. Field name and protocol name are the same string, so a limit
        /// greps from a plan's `analysis.limits` to the code that reads it.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct AnalysisLimits {
            $(pub $field: u64,)*
        }

        impl Default for AnalysisLimits {
            fn default() -> Self {
                Self { $($field: $default,)* }
            }
        }

        impl AnalysisLimits {
            /// Every limit name the engine knows, in protocol-map order.
            pub const NAMES: &'static [&'static str] = &[$(stringify!($field),)*];

            /// Read a protocol limits map. Every known name must be present
            /// and no unknown name may appear.
            pub fn from_map(limits: &Limits) -> Result<Self, LimitsError> {
                for name in limits.keys() {
                    if !Self::NAMES.contains(&name.as_str()) {
                        return Err(LimitsError::Unknown(name.clone()));
                    }
                }
                Ok(Self {
                    $($field: *limits
                        .get(stringify!($field))
                        .ok_or_else(|| LimitsError::Missing(stringify!($field).to_string()))?,)*
                })
            }

            /// The protocol map written to `analysis.limits`.
            pub fn to_map(&self) -> Limits {
                Limits::from([$((stringify!($field).to_string(), self.$field),)*])
            }
        }
    };
}

/// Per-frontend AST node caps. Named consts because summary and repository
/// fact walks run without a plan's limits in scope and must use the same
/// bound as the analysis path.
pub(crate) const DEFAULT_MAX_PYTHON_NODES: u64 = 80_000;
pub(crate) const DEFAULT_MAX_JS_NODES: u64 = 20_000;
pub(crate) const DEFAULT_MAX_PHP_NODES: u64 = 20_000;
pub(crate) const DEFAULT_MAX_JAVA_NODES: u64 = 30_000;
pub(crate) const DEFAULT_MAX_GO_NODES: u64 = 80_000;
pub(crate) const DEFAULT_MAX_RUBY_NODES: u64 = 20_000;
pub(crate) const DEFAULT_MAX_RUST_NODES: u64 = 20_000;

analysis_limits! {
    // Deterministic whole-analysis work and retained-memory budget. Steps are
    // sized from the bench `pathological` case (500 commands plus a 40-deep
    // `sh -c` chain, ~11k steps): the smallest power of two at least twice
    // the measured work. See the bench output for the measured steps/ms.
    max_analysis_steps = 32_768,
    max_analysis_bytes = 32 * 1024 * 1024,
    max_effects = 4096,
    max_value_depth = 24,
    max_value_cardinality = 64,
    max_execution_depth = 8,
    max_shell_function_depth = 8,
    max_execution_nodes = 4096,
    max_execution_fanout = 256,
    max_shell_words = 4096,
    max_heredoc_expansions = 4096,
    // Sized against the other caps: 4096 execution nodes alone mint two
    // nodes each, plus span/model/argument nodes per effect and boundary.
    max_provenance_nodes = 65536,
    max_boundaries = 4096,
    max_source_bytes = 4 * 1024 * 1024,
    max_resolved_source_files = 64,
    // Distinct external host observations one analysis may demand. Sized like
    // the resolved-source bound: a subject naming more than this many distinct
    // paths whose identity matters is already past the evidence this channel
    // can carry, and each further demand becomes a boundary rather than a walk.
    max_observation_requests = 64,
    max_source_alternatives = 32,
    max_patch_bytes = 4_194_304,
    max_patch_files = 2_048,
    max_causal_nodes = 16_384,
    max_causal_edges = 32_768,
    max_causal_depth = 256,
    max_causal_pairs = 32_768,
    // Per-frontend AST node caps. They draw from the same step pool, so these
    // bound one frontend's walk while `max_analysis_steps` bounds the run.
    max_python_nodes = DEFAULT_MAX_PYTHON_NODES,
    max_js_nodes = DEFAULT_MAX_JS_NODES,
    max_php_nodes = DEFAULT_MAX_PHP_NODES,
    max_java_nodes = DEFAULT_MAX_JAVA_NODES,
    max_go_nodes = DEFAULT_MAX_GO_NODES,
    max_ruby_nodes = DEFAULT_MAX_RUBY_NODES,
    max_rust_nodes = DEFAULT_MAX_RUST_NODES,
}

/// One struct or vector node in the accounted-byte schedule.
pub(crate) const NODE_BYTES: u64 = 32;

/// A callable may consume at most one eighth of the Python node allowance.
pub(crate) const PYTHON_CALLABLE_BUDGET_DIVISOR: u64 = 8;

/// Accounted bytes retained by one effect, under a fixed schedule: every
/// `String` costs its `len()`, every struct or vector node costs 32. The
/// schedule is deliberately platform-independent — never `size_of`, never
/// RSS — so `max_analysis_bytes` saturates identically on every host, and it
/// is part of the engine version.
pub(crate) fn retained_bytes(effect: &Effect) -> u64 {
    let mut bytes =
        NODE_BYTES + effinterp_proto::EffectId::BYTES as u64 + effect.operation.0.len() as u64;
    bytes += resource_bytes(&effect.resource);
    bytes += realm_bytes(&effect.realm);
    for (name, value) in &effect.attributes {
        bytes += NODE_BYTES + name.len() as u64;
        if let AttrValue::String(text) = value {
            bytes += text.len() as u64;
        }
    }
    if let Some(condition) = &effect.condition {
        bytes += NODE_BYTES + condition.retained_bytes();
    }
    bytes += NODE_BYTES + effect.provenance.len() as u64 * NODE_BYTES;
    bytes
}

pub(crate) fn boundary_retained_bytes(boundary: &effinterp_proto::Boundary) -> u64 {
    NODE_BYTES * (3 + boundary.domains.len() as u64 + boundary.provenance.len() as u64)
        + boundary.reason.as_str().len() as u64
        + boundary
            .domains
            .iter()
            .map(|domain| domain.0.len() as u64)
            .sum::<u64>()
        + boundary.limit.as_ref().map_or(0, |text| text.len() as u64)
        + boundary.detail.as_ref().map_or(0, |text| text.len() as u64)
        + boundary.callee.as_ref().map_or(0, |callee| {
            NODE_BYTES + callee.module.len() as u64 + callee.symbol.len() as u64
        })
        + boundary
            .affected_resource
            .as_ref()
            .map_or(0, resource_bytes)
}

/// Accounted bytes retained by one recorded transfer binding: two slots under
/// the same fixed schedule the effect meter uses.
pub(crate) fn transfer_binding_bytes() -> u64 {
    2 * NODE_BYTES
}

/// Reserve finalization's normalized tuple, escaped JSON group key, map nodes,
/// and validator's expected ID. The group key and stable-hash serialization
/// can each expand a string byte to six bytes; reserve the remaining copies
/// too. Identity contains the realm twice. Retained ID storage itself is
/// charged exactly once by `retained_bytes`, even on copied effects.
pub(crate) fn effect_id_scratch_bytes(effect: &Effect) -> u64 {
    let (condition_bytes, condition_scratch) =
        effect.condition.as_ref().map_or((0, 0), |condition| {
            let bytes = condition.retained_bytes();
            // Projection clones the evidence once, then strips it. Escaped keys
            // and hash inputs contain only structural identity, never source text.
            (bytes, bytes + 16 * condition.identity().retained_bytes())
        });
    16 * (retained_bytes(effect) - effinterp_proto::EffectId::BYTES as u64 - condition_bytes
        + realm_bytes(&effect.realm))
        + condition_scratch
        + 16 * NODE_BYTES
}

/// Accounted bytes retained by one additional execution node. The root node
/// is the required subject echo and is created without this charge.
pub(crate) fn execution_node_retained_bytes(node: &ExecutionNode) -> u64 {
    NODE_BYTES
        + NODE_BYTES
        + node.argv.iter().map(resource_bytes).sum::<u64>()
        + node.cwd.as_ref().map(resource_bytes).unwrap_or(0)
        + realm_bytes(&node.realm)
        + node.input.as_ref().map_or(0, |input| {
            serde_json::to_vec(input)
                .expect("execution input serialization")
                .len() as u64
        })
}

fn realm_bytes(realm: &ExecutionRealm) -> u64 {
    let inner = match realm {
        ExecutionRealm::Host => 0,
        ExecutionRealm::Container { runtime, name } => (runtime.len() + name.len()) as u64,
        ExecutionRealm::Kubernetes {
            namespace,
            pod,
            container,
        } => optional_text_bytes(namespace) + pod.len() as u64 + optional_text_bytes(container),
        ExecutionRealm::Chroot { host_root } => optional_text_bytes(host_root),
        ExecutionRealm::Remote { endpoint } => endpoint.len() as u64,
    };
    NODE_BYTES + inner
}

/// Accounted bytes of a resource expression tree, same schedule.
pub(crate) fn resource_bytes(expr: &ResourceExpr) -> u64 {
    let inner = match expr {
        ResourceExpr::Concrete { identity } => identity_bytes(identity),
        ResourceExpr::Literal { value } => value.len() as u64,
        ResourceExpr::Parameter { name } | ResourceExpr::Environment { name } => name.len() as u64,
        ResourceExpr::Property { base, name } => resource_bytes(base) + name.len() as u64,
        ResourceExpr::Join { parts } => NODE_BYTES + parts.iter().map(resource_bytes).sum::<u64>(),
        ResourceExpr::Union { alternatives } => {
            NODE_BYTES + alternatives.iter().map(resource_bytes).sum::<u64>()
        }
        ResourceExpr::Pattern { pattern } => pattern_bytes(pattern),
        ResourceExpr::Unresolved { family } => family.0.len() as u64,
    };
    NODE_BYTES + inner
}

fn optional_resource_bytes(expr: &Option<Box<ResourceExpr>>) -> u64 {
    expr.as_deref().map(resource_bytes).unwrap_or(0)
}

fn identity_bytes(identity: &ResourceIdentity) -> u64 {
    let inner = match identity {
        ResourceIdentity::ServiceUnit { manager, name }
        | ResourceIdentity::StorageVolume { manager, name } => (manager.len() + name.len()) as u64,
        ResourceIdentity::ScheduledJob { scheduler, owner } => {
            scheduler.len() as u64 + optional_text_bytes(owner)
        }
        ResourceIdentity::BlockDevice { device } => device.len() as u64,
        ResourceIdentity::KubernetesResource {
            api_group, kind, ..
        } => {
            (api_group.len() + kind.len()) as u64
                + identity
                    .infrastructure_values()
                    .into_iter()
                    .map(resource_bytes)
                    .sum::<u64>()
        }
        ResourceIdentity::ManagedInfrastructure {
            tool,
            resource_type,
            address,
            ..
        } => {
            tool.len() as u64
                + optional_text_bytes(resource_type)
                + optional_text_bytes(address)
                + identity
                    .infrastructure_values()
                    .into_iter()
                    .map(resource_bytes)
                    .sum::<u64>()
        }
        ResourceIdentity::Artifact {
            endpoint,
            name,
            reference,
            ..
        } => {
            NODE_BYTES
                + resource_bytes(endpoint)
                + resource_bytes(name)
                + reference.value().map(resource_bytes).unwrap_or(0)
        }
        ResourceIdentity::CredentialStore {
            provider,
            store,
            path,
        } => provider.len() as u64 + optional_text_bytes(store) + optional_text_bytes(path),
        ResourceIdentity::HostSystem {} => 0,
        ResourceIdentity::FsPath { path } => path.len() as u64,
        ResourceIdentity::UserHome { user } => user.len() as u64,
        ResourceIdentity::EnvironmentVariable { name } => name.len() as u64,
        ResourceIdentity::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => {
            optional_resource_bytes(worktree)
                + optional_resource_bytes(git_dir)
                + optional_resource_bytes(pathspec)
        }
        ResourceIdentity::Process {
            executable,
            path,
            argv,
            cwd,
        } => {
            executable.len() as u64
                + path.as_ref().map(|p| p.len() as u64).unwrap_or(0)
                + NODE_BYTES
                + argv.iter().map(resource_bytes).sum::<u64>()
                + optional_resource_bytes(cwd)
        }
        ResourceIdentity::NetworkEndpoint {
            host,
            scheme,
            port: _,
            path,
        } => {
            host.len() as u64
                + scheme.as_ref().map(|s| s.len() as u64).unwrap_or(0)
                + path.as_ref().map(|p| p.len() as u64).unwrap_or(0)
        }
        ResourceIdentity::Container {
            runtime,
            name,
            image,
            storage,
        } => {
            runtime.len() as u64
                + name.as_ref().map(|n| n.len() as u64).unwrap_or(0)
                + image.as_ref().map(|i| i.len() as u64).unwrap_or(0)
                + NODE_BYTES
                + storage.iter().map(storage_bytes).sum::<u64>()
        }
        ResourceIdentity::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => {
            optional_text_bytes(server)
                + optional_text_bytes(database)
                + optional_text_bytes(schema)
                + table.len() as u64
        }
        ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema,
        } => {
            optional_text_bytes(server)
                + optional_text_bytes(database)
                + optional_text_bytes(schema)
        }
        ResourceIdentity::ObjectStore {
            provider,
            bucket,
            key,
            ..
        } => optional_text_bytes(provider) + bucket.len() as u64 + optional_text_bytes(key),
        ResourceIdentity::CloudResource {
            provider,
            service,
            kind,
            id,
            ..
        } => {
            optional_text_bytes(provider)
                + (service.len() + kind.len()) as u64
                + optional_text_bytes(id)
        }
        ResourceIdentity::MessageTopic { system, name, .. } => {
            optional_text_bytes(system) + name.len() as u64
        }
    };
    NODE_BYTES
        + inner
        + identity.scope().map_or(0, |scope| {
            scope.values().map(resource_bytes).sum::<u64>()
                + scope
                    .access
                    .iter()
                    .filter_map(|e| e.origin.as_ref())
                    .map(realm_bytes)
                    .sum::<u64>()
                + (scope.identity.len() + scope.access.len()) as u64 * NODE_BYTES
        })
}

fn optional_text_bytes(text: &Option<String>) -> u64 {
    text.as_ref().map(|t| t.len() as u64).unwrap_or(0)
}

fn storage_bytes(storage: &ContainerStorage) -> u64 {
    let inner = match storage {
        ContainerStorage::BindMount {
            host_path,
            container_path,
            read_only: _,
        } => resource_bytes(host_path) + resource_bytes(container_path),
        ContainerStorage::Volume {
            name,
            container_path,
        } => name.len() as u64 + resource_bytes(container_path),
    };
    NODE_BYTES + inner
}

#[cfg(test)]
mod tests {
    use super::*;
    use effinterp_proto::{ExecutionNodeRef, Modality, Operation};

    fn effect(resource: ResourceExpr) -> Effect {
        Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("filesystem.read"),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: Default::default(),
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: Vec::new(),
        }
    }

    #[test]
    fn retained_byte_schedule_charges_vector_nodes() {
        let literal = retained_bytes(&effect(ResourceExpr::Literal {
            value: String::new(),
        }));
        let join = retained_bytes(&effect(ResourceExpr::Join { parts: Vec::new() }));
        let union = retained_bytes(&effect(ResourceExpr::Union {
            alternatives: Vec::new(),
        }));
        assert_eq!(join - literal, NODE_BYTES);
        assert_eq!(union - literal, NODE_BYTES);

        let path = retained_bytes(&effect(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: String::new(),
            },
        }));
        let process = retained_bytes(&effect(ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: String::new(),
                path: None,
                argv: Vec::new(),
                cwd: None,
            },
        }));
        let container = retained_bytes(&effect(ResourceExpr::Concrete {
            identity: ResourceIdentity::Container {
                runtime: String::new(),
                name: None,
                image: None,
                storage: Vec::new(),
            },
        }));
        assert_eq!(process - path, NODE_BYTES);
        assert_eq!(container - path, NODE_BYTES);
    }

    #[test]
    fn effect_ids_are_charged_once_before_accepting_an_effect() {
        use crate::builder::PlanBuilder;
        use effinterp_proto::{CoverageLevel, Domain, EffectId, Subject};
        let mut effect = effect(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/file".into(),
            },
        });
        // 32-byte effect, 15-byte operation, 69-byte resource, 32-byte realm,
        // and 32-byte provenance vector, plus the required serialized ID.
        assert_eq!(retained_bytes(&effect), 180 + EffectId::BYTES as u64);
        effect.id = EffectId(format!("effect:blake3:{}", "a".repeat(64)));
        assert_eq!(retained_bytes(&effect), 180 + effect.id.0.len() as u64);
        let subject = Subject::Exec {
            argv: vec!["cat".into()],
            cwd: None,
            context: Default::default(),
        };
        let without_id = 180
            + effect_id_scratch_bytes(&effect)
            + effinterp_proto::canonical_json(&subject).len() as u64
            + 4 * NODE_BYTES;
        let mut builder = PlanBuilder::new(
            subject,
            "test".into(),
            "test".into(),
            AnalysisLimits {
                max_analysis_bytes: without_id,
                ..Default::default()
            },
        );
        builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
        builder.effect(effect);
        let plan = builder.finish().unwrap();
        assert!(plan.effects.is_empty());
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.limit.as_deref() == Some("max_analysis_bytes"))
        );
    }

    #[test]
    fn retained_byte_schedule_charges_execution_realms() {
        assert_eq!(realm_bytes(&ExecutionRealm::Host), NODE_BYTES);
        assert_eq!(
            realm_bytes(&ExecutionRealm::Container {
                runtime: "docker".into(),
                name: "worker".into(),
            }),
            NODE_BYTES + 12
        );
        assert_eq!(
            realm_bytes(&ExecutionRealm::Kubernetes {
                namespace: Some("prod".into()),
                pod: "api".into(),
                container: Some("web".into()),
            }),
            NODE_BYTES + 10
        );
        assert_eq!(
            realm_bytes(&ExecutionRealm::Chroot {
                host_root: Some("/srv/root".into()),
            }),
            NODE_BYTES + 9
        );
        assert_eq!(
            realm_bytes(&ExecutionRealm::Remote {
                endpoint: "host.example".into(),
            }),
            NODE_BYTES + 12
        );
    }
}

fn pattern_bytes(pattern: &effinterp_proto::ResourcePattern) -> u64 {
    use effinterp_proto::{Field, ResourcePattern, TextField};
    let field = |field: &Field| {
        NODE_BYTES
            + match field {
                Field::Any => 0,
                Field::Exact { value } => value.len() as u64,
            }
    };
    let inner = match pattern {
        ResourcePattern::FsPath { glob } => glob.len() as u64,
        ResourcePattern::EnvironmentVariable { name_glob } => name_glob.len() as u64,
        ResourcePattern::NetworkEndpoint {
            host_glob,
            scheme,
            path_prefix,
            ..
        } => host_glob.len() as u64 + field(scheme) + NODE_BYTES + optional_text_bytes(path_prefix),
        ResourcePattern::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => field(server) + field(database) + field(schema) + field(table),
        ResourcePattern::DatabaseSchema {
            server,
            database,
            schema,
        } => field(server) + field(database) + field(schema),
        ResourcePattern::Process {
            executable,
            argv_prefix,
        } => {
            NODE_BYTES
                + match executable {
                    TextField::Any => 0,
                    TextField::Exact { value } => value.len() as u64,
                    TextField::Glob { glob } => glob.len() as u64,
                }
                + NODE_BYTES
                + argv_prefix.iter().map(resource_bytes).sum::<u64>()
        }
        ResourcePattern::ObjectStore {
            provider,
            bucket,
            key_prefix,
        } => field(provider) + bucket.len() as u64 + optional_text_bytes(key_prefix),
        ResourcePattern::Container {
            runtime,
            name_glob,
            image_glob,
        } => field(runtime) + optional_text_bytes(name_glob) + optional_text_bytes(image_glob),
        ResourcePattern::GitRepository {
            worktree,
            git_dir,
            pathspec_glob,
        } => {
            optional_text_bytes(worktree)
                + optional_text_bytes(git_dir)
                + optional_text_bytes(pathspec_glob)
        }
        ResourcePattern::CloudResource {
            provider,
            service,
            kind,
            id_glob,
        } => field(provider) + field(service) + field(kind) + id_glob.len() as u64,
        ResourcePattern::MessageTopic { system, name_glob } => {
            field(system) + name_glob.len() as u64
        }
        ResourcePattern::ArtifactField { glob } => glob.len() as u64,
        ResourcePattern::ServiceUnit { manager, name_glob } => {
            field(manager) + name_glob.len() as u64
        }
    };
    NODE_BYTES + inner
}

/// Node cap for each callable or initializer walk during summary extraction.
#[derive(Debug, Clone)]
pub struct SummaryBudget {
    limit: &'static str,
    pub value_limits: crate::ValueLimits,
    pub max_nodes: u64,
    pub steps: std::cell::Cell<u64>,
    /// Steps spent inferring value facts across the whole extraction. Walks
    /// reset `steps`; this total never resets, so it shows whether each
    /// function's facts were inferred once. Counted, not a limit.
    pub value_steps: std::cell::Cell<u64>,
}

impl SummaryBudget {
    pub fn new(max_nodes: u64) -> Self {
        Self {
            limit: "max_summary_nodes",
            max_nodes,
            value_limits: AnalysisLimits::default().value_limits(),
            steps: std::cell::Cell::new(0),
            value_steps: std::cell::Cell::new(0),
        }
    }

    pub fn for_lang(limits: &effinterp_proto::Limits, lang: crate::Lang) -> Self {
        Self {
            limit: Self::limit_name(lang),
            value_limits: AnalysisLimits::from_map(limits)
                .expect("validated summary limits")
                .value_limits(),
            ..Self::new(limits[Self::limit_name(lang)])
        }
    }

    pub fn limit_name(lang: crate::Lang) -> &'static str {
        match lang {
            crate::Lang::Python => "max_python_nodes",
            crate::Lang::Js(_) => "max_js_nodes",
            crate::Lang::Go => "max_go_nodes",
            crate::Lang::Ruby => "max_ruby_nodes",
            crate::Lang::Rust => "max_rust_nodes",
            crate::Lang::Java => "max_java_nodes",
            crate::Lang::Php => "max_php_nodes",
        }
    }

    pub(crate) fn enter(&self) -> SummaryScope<'_> {
        let current = std::rc::Rc::new(Self::new(self.max_nodes));
        let previous = SUMMARY_BUDGET.with(|slot| slot.replace(Some(current.clone())));
        SummaryScope {
            owner: self,
            current,
            previous,
        }
    }
}

// Summary inference and invocation share recursive walkers. A scoped meter lets
// those walkers charge the current walk without changing invocation Budget.
thread_local! {
    static SUMMARY_BUDGET: std::cell::RefCell<Option<std::rc::Rc<SummaryBudget>>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct SummaryScope<'a> {
    owner: &'a SummaryBudget,
    current: std::rc::Rc<SummaryBudget>,
    previous: Option<std::rc::Rc<SummaryBudget>>,
}
impl Drop for SummaryScope<'_> {
    fn drop(&mut self) {
        self.owner.steps.set(self.current.steps.get());
        self.owner.value_steps.set(
            self.owner
                .value_steps
                .get()
                .saturating_add(self.current.value_steps.get()),
        );
        SUMMARY_BUDGET.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}

pub(crate) fn summary_step() -> bool {
    if crate::guards::invocation_timed_out() {
        return false;
    }
    summary_charge(1).is_ok()
}

/// Record value-fact inference work on the current extraction, if any.
pub(crate) fn note_summary_value_steps(steps: u64) {
    SUMMARY_BUDGET.with(|slot| {
        if let Some(budget) = slot.borrow().as_ref() {
            budget
                .value_steps
                .set(budget.value_steps.get().saturating_add(steps));
        }
    });
}

/// Charge the current summary walk. A walk with no meter is never over it.
pub(crate) fn summary_charge(steps: u64) -> Result<(), &'static str> {
    charge_summary(steps).unwrap_or(Ok(()))
}

/// Charge the current summary walk, reporting the absence of a meter as
/// `None` so callers can fall back to the whole-analysis step budget.
pub(crate) fn summary_steps(steps: u64) -> Option<bool> {
    charge_summary(steps).map(|charged| charged.is_ok())
}

fn charge_summary(steps: u64) -> Option<Result<(), &'static str>> {
    SUMMARY_BUDGET.with(|slot| {
        let slot = slot.borrow();
        let budget = slot.as_ref()?;
        let steps = budget.steps.get().saturating_add(steps);
        budget.steps.set(steps);
        Some(if steps <= budget.max_nodes {
            Ok(())
        } else {
            Err(budget.limit)
        })
    })
}

// Extraction uses the configured language cap, invocation its own local cap.
pub(crate) fn invocation_node_limit(invocation_limit: u64) -> u64 {
    SUMMARY_BUDGET.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(invocation_limit, |budget| budget.max_nodes)
    })
}

/// Start an independent callable or initializer walk; nested inlining keeps
/// charging its caller. Restore the enclosing meter when this walk finishes.
pub(crate) fn summary_walk() -> SummaryWalk {
    let budget = SUMMARY_BUDGET.with(|slot| slot.borrow().clone());
    let previous_steps = budget.as_ref().map_or(0, |budget| budget.steps.replace(0));
    SummaryWalk {
        budget,
        previous_steps,
    }
}

pub(crate) struct SummaryWalk {
    budget: Option<std::rc::Rc<SummaryBudget>>,
    previous_steps: u64,
}

impl SummaryWalk {
    pub(crate) fn is_active(&self) -> bool {
        self.budget.is_some()
    }
}

impl Drop for SummaryWalk {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.steps.set(self.previous_steps);
        }
    }
}

impl AnalysisLimits {
    /// Widening bounds recorded in this analysis's limits map.
    pub fn value_limits(&self) -> crate::ValueLimits {
        self.into()
    }
}
