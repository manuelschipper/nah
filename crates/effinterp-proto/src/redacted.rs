//! The redacted plan: the same effects, boundaries, and graphs with its literals
//! replaced by a digest that still correlates across plans. It lets a plan be
//! shared, as `analyze --redact` output or a conformance case, without
//! disclosing the literal paths, arguments, and string values it was built from.
//!
//! Redaction limits: this is a literal-redaction projection, not anonymization.
//! See [`redact_plan`] for the identifiers and scalar values that stay visible and
//! the distinctions the redacted representation drops.

use crate::{
    Analysis, ArtifactEcosystem, ArtifactReference, AttrValue, Boundary, BoundaryClass,
    BoundaryReason, BoundaryRef, ByteSpan, CalleeReference, CausalCardinality, CausalEdge,
    CausalReason, Causality, Condition, ContainerStorage, Coverage, CoverageClaim, Domain, Effect,
    EffectId, ExecutionAssurance, ExecutionContent, ExecutionEdge, ExecutionGraph, ExecutionInput,
    ExecutionInputRole, ExecutionNode, ExecutionNodeRef, ExecutionPhase, ExecutionRealm,
    ExecutionSelection, ExecutionSelector, ExecutionStreamRef, ExecutionStreamValue,
    ExecutionStreams, KubernetesNamespace, Modality, NamespaceKind, OccurrenceId, OccurrenceKind,
    OccurrenceNode, Operation, Plan, Port, ProvenanceKind, ProvenanceNode, ProvenanceRef,
    REDACTED_LITERAL_HASH_DOMAIN, RequestAssurance, ResourceExpr, ResourceFamily, ResourceIdentity,
    ResourceScope, ScopeDimension, ScopeEvidence, ScopeEvidenceKind, ScopeValue, Subject,
    canonical_hash, stable_hash,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const REDACTED_SCHEMA_V1: &str = "effinterp/plan-redacted/v1";

fn digest(value: &str) -> String {
    stable_hash(REDACTED_LITERAL_HASH_DOMAIN, &value)[..23].to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedContainerStorage {
    BindMount {
        host_path: ResourceShape,
        container_path: ResourceShape,
        read_only: bool,
    },
    Volume {
        name: String,
        container_path: ResourceShape,
    },
}

impl RedactedContainerStorage {
    fn from(value: &ContainerStorage) -> Self {
        match value {
            ContainerStorage::BindMount {
                host_path,
                container_path,
                read_only,
            } => Self::BindMount {
                host_path: ResourceShape::from(host_path),
                container_path: ResourceShape::from(container_path),
                read_only: *read_only,
            },
            ContainerStorage::Volume {
                name,
                container_path,
            } => Self::Volume {
                name: digest(name),
                container_path: ResourceShape::from(container_path),
            },
        }
    }
}

impl RedactedContainerStorage {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::BindMount {
                host_path,
                container_path,
                ..
            } => {
                host_path.check(errors);
                container_path.check(errors);
            }
            Self::Volume {
                name,
                container_path,
                ..
            } => {
                check_digest(name, 16, errors);
                container_path.check(errors);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedKubernetesNamespace {
    Cluster,
    Namespaced { namespace: Box<ResourceShape> },
    Unknown { namespace: Box<ResourceShape> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceShapeIdentity {
    Artifact {
        ecosystem: ArtifactEcosystem,
        endpoint: Box<ResourceShape>,
        name: Box<ResourceShape>,
        reference: Box<ArtifactReference<ResourceShape>>,
    },
    ServiceUnit {
        manager: String,
        name: String,
    },
    ScheduledJob {
        scheduler: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
    StorageVolume {
        manager: String,
        name: String,
    },
    BlockDevice {
        device: String,
    },
    CredentialStore {
        provider: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        store: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    HostSystem {},
    FsPath {
        digest: String,
    },
    UserHome {
        digest: String,
    },
    EnvironmentVariable {
        name: String,
    },

    GitRepository {
        #[serde(skip_serializing_if = "Option::is_none")]
        worktree: Option<Box<ResourceShape>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        git_dir: Option<Box<ResourceShape>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pathspec: Option<Box<ResourceShape>>,
    },
    Process {
        executable: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        argv: Vec<ResourceShape>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<Box<ResourceShape>>,
    },
    NetworkEndpoint {
        host: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },

    Container {
        runtime: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        storage: Vec<RedactedContainerStorage>,
    },

    KubernetesResource {
        api_group: String,
        kind: String,
        name: Box<ResourceShape>,
        namespace: RedactedKubernetesNamespace,
        server: Box<ResourceShape>,
        context: Box<ResourceShape>,
    },
    ManagedInfrastructure {
        tool: String,
        configuration_root: Box<ResourceShape>,
        workspace: Box<ResourceShape>,
        resource_type: Option<String>,
        address: Option<String>,
        instance: Box<ResourceShape>,
    },
    DatabaseTable {
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
        table: String,
    },

    DatabaseSchema {
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
    },

    ObjectStore {
        scope: Box<RedactedResourceScope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        bucket: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },

    CloudResource {
        scope: Box<RedactedResourceScope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        service: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },

    MessageTopic {
        scope: Box<RedactedResourceScope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        system: Option<String>,
        name: String,
    },
}

impl ResourceShapeIdentity {
    fn from(value: &ResourceIdentity) -> Self {
        match value {
            ResourceIdentity::Artifact {
                ecosystem,
                endpoint,
                name,
                reference,
            } => Self::Artifact {
                ecosystem: *ecosystem,
                endpoint: Box::new(ResourceShape::from(endpoint.as_ref())),
                name: Box::new(ResourceShape::from(name.as_ref())),
                reference: Box::new(reference.as_ref().map(ResourceShape::from)),
            },
            ResourceIdentity::ServiceUnit { manager, name } => Self::ServiceUnit {
                manager: manager.clone(),
                name: digest(name),
            },
            ResourceIdentity::ScheduledJob { scheduler, owner } => Self::ScheduledJob {
                scheduler: scheduler.clone(),
                owner: owner.as_ref().map(|value| digest(value)),
            },
            ResourceIdentity::StorageVolume { manager, name } => Self::StorageVolume {
                manager: manager.clone(),
                name: digest(name),
            },
            ResourceIdentity::BlockDevice { device } => Self::BlockDevice {
                device: digest(device),
            },
            ResourceIdentity::CredentialStore {
                provider,
                store,
                path,
            } => Self::CredentialStore {
                provider: provider.clone(),
                store: store.as_ref().map(|value| digest(value)),
                path: path.as_ref().map(|value| digest(value)),
            },
            ResourceIdentity::HostSystem {} => Self::HostSystem {},
            ResourceIdentity::FsPath { path } => Self::FsPath {
                digest: digest(path),
            },
            ResourceIdentity::UserHome { user } => Self::UserHome {
                digest: digest(user),
            },
            ResourceIdentity::EnvironmentVariable { name } => {
                Self::EnvironmentVariable { name: name.clone() }
            }
            ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => Self::GitRepository {
                worktree: worktree
                    .as_ref()
                    .map(|value| Box::new(ResourceShape::from(value.as_ref()))),
                git_dir: git_dir
                    .as_ref()
                    .map(|value| Box::new(ResourceShape::from(value.as_ref()))),
                pathspec: pathspec
                    .as_ref()
                    .map(|value| Box::new(ResourceShape::from(value.as_ref()))),
            },
            ResourceIdentity::Process {
                executable,
                path,
                argv,
                cwd,
            } => Self::Process {
                executable: executable.rsplit('/').next().unwrap_or("").to_string(),
                path: path.as_ref().map(|value| digest(value)),
                argv: argv.iter().map(ResourceShape::from).collect(),
                cwd: cwd
                    .as_ref()
                    .map(|value| Box::new(ResourceShape::from(value.as_ref()))),
            },
            ResourceIdentity::NetworkEndpoint {
                host,
                scheme,
                port,
                path,
            } => Self::NetworkEndpoint {
                host: digest(host),
                scheme: scheme.clone(),
                port: port.as_ref().map(|value| *value),
                path: path.as_ref().map(|value| digest(value)),
            },
            ResourceIdentity::Container {
                runtime,
                name,
                image,
                storage,
            } => Self::Container {
                runtime: runtime.clone(),
                name: name.as_ref().map(|value| digest(value)),
                image: image.as_ref().map(|value| digest(value)),
                storage: storage.iter().map(RedactedContainerStorage::from).collect(),
            },
            ResourceIdentity::KubernetesResource {
                api_group,
                kind,
                name,
                namespace,
                server,
                context,
            } => Self::KubernetesResource {
                api_group: api_group.clone(),
                kind: kind.clone(),
                name: Box::new(ResourceShape::from(name.as_ref())),
                namespace: match namespace {
                    KubernetesNamespace::Cluster => RedactedKubernetesNamespace::Cluster,
                    KubernetesNamespace::Namespaced { namespace } => {
                        RedactedKubernetesNamespace::Namespaced {
                            namespace: Box::new(ResourceShape::from(namespace.as_ref())),
                        }
                    }
                    KubernetesNamespace::Unknown { namespace } => {
                        RedactedKubernetesNamespace::Unknown {
                            namespace: Box::new(ResourceShape::from(namespace.as_ref())),
                        }
                    }
                },
                server: Box::new(ResourceShape::from(server.as_ref())),
                context: Box::new(ResourceShape::from(context.as_ref())),
            },
            ResourceIdentity::ManagedInfrastructure {
                tool,
                configuration_root,
                workspace,
                resource_type,
                address,
                instance,
            } => Self::ManagedInfrastructure {
                tool: tool.clone(),
                configuration_root: Box::new(ResourceShape::from(configuration_root.as_ref())),
                workspace: Box::new(ResourceShape::from(workspace.as_ref())),
                resource_type: resource_type.clone(),
                address: address.as_ref().map(|value| digest(value)),
                instance: Box::new(ResourceShape::from(instance.as_ref())),
            },
            ResourceIdentity::DatabaseTable {
                server,
                database,
                schema,
                table,
            } => Self::DatabaseTable {
                server: server.as_ref().map(|value| digest(value)),
                database: database.as_ref().map(|value| digest(value)),
                schema: schema.as_ref().map(|value| digest(value)),
                table: digest(table),
            },
            ResourceIdentity::DatabaseSchema {
                server,
                database,
                schema,
            } => Self::DatabaseSchema {
                server: server.as_ref().map(|value| digest(value)),
                database: database.as_ref().map(|value| digest(value)),
                schema: schema.as_ref().map(|value| digest(value)),
            },
            ResourceIdentity::ObjectStore {
                scope,
                provider,
                bucket,
                key,
            } => Self::ObjectStore {
                scope: Box::new(RedactedResourceScope::from(scope.as_ref())),
                provider: provider.clone(),
                bucket: digest(bucket),
                key: key.as_ref().map(|value| digest(value)),
            },
            ResourceIdentity::CloudResource {
                scope,
                provider,
                service,
                kind,
                id,
            } => Self::CloudResource {
                scope: Box::new(RedactedResourceScope::from(scope.as_ref())),
                provider: provider.clone(),
                service: service.clone(),
                kind: kind.clone(),
                id: id.as_ref().map(|value| digest(value)),
            },
            ResourceIdentity::MessageTopic {
                scope,
                system,
                name,
            } => Self::MessageTopic {
                scope: Box::new(RedactedResourceScope::from(scope.as_ref())),
                system: system.clone(),
                name: digest(name),
            },
        }
    }
}

impl ResourceShapeIdentity {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::Artifact {
                endpoint,
                name,
                reference,
                ..
            } => {
                endpoint.as_ref().check(errors);
                name.as_ref().check(errors);
                if let Some(value) = reference.as_ref().value() {
                    value.check(errors);
                }
            }
            Self::KubernetesResource {
                name,
                namespace,
                server,
                context,
                ..
            } => {
                name.check(errors);
                server.check(errors);
                context.check(errors);
                match namespace {
                    RedactedKubernetesNamespace::Cluster => {}
                    RedactedKubernetesNamespace::Namespaced { namespace }
                    | RedactedKubernetesNamespace::Unknown { namespace } => namespace.check(errors),
                }
            }
            Self::ManagedInfrastructure {
                configuration_root,
                workspace,
                address,
                instance,
                ..
            } => {
                configuration_root.check(errors);
                workspace.check(errors);
                instance.check(errors);
                if let Some(address) = address {
                    check_digest(address, 16, errors);
                }
            }
            Self::ServiceUnit { name, .. } => {
                check_digest(name, 16, errors);
            }
            Self::ScheduledJob { owner, .. } => {
                if let Some(value) = owner {
                    check_digest(value, 16, errors);
                }
            }
            Self::StorageVolume { name, .. } => {
                check_digest(name, 16, errors);
            }
            Self::BlockDevice { device, .. } => {
                check_digest(device, 16, errors);
            }
            Self::CredentialStore { store, path, .. } => {
                if let Some(value) = store {
                    check_digest(value, 16, errors);
                }
                if let Some(value) = path {
                    check_digest(value, 16, errors);
                }
            }
            Self::HostSystem { .. } => {}
            Self::FsPath { digest, .. } | Self::UserHome { digest } => {
                check_digest(digest, 16, errors);
            }
            Self::EnvironmentVariable { .. } => {}
            Self::GitRepository {
                worktree,
                git_dir,
                pathspec,
                ..
            } => {
                if let Some(value) = worktree {
                    value.as_ref().check(errors);
                }
                if let Some(value) = git_dir {
                    value.as_ref().check(errors);
                }
                if let Some(value) = pathspec {
                    value.as_ref().check(errors);
                }
            }
            Self::Process {
                path, argv, cwd, ..
            } => {
                if let Some(value) = path {
                    check_digest(value, 16, errors);
                }
                for value in argv {
                    value.check(errors);
                }
                if let Some(value) = cwd {
                    value.as_ref().check(errors);
                }
            }
            Self::NetworkEndpoint { host, path, .. } => {
                check_digest(host, 16, errors);
                if let Some(value) = path {
                    check_digest(value, 16, errors);
                }
            }
            Self::Container {
                name,
                image,
                storage,
                ..
            } => {
                if let Some(value) = name {
                    check_digest(value, 16, errors);
                }
                if let Some(value) = image {
                    check_digest(value, 16, errors);
                }
                for value in storage {
                    value.check(errors);
                }
            }
            Self::DatabaseTable {
                server,
                database,
                schema,
                table,
                ..
            } => {
                if let Some(value) = server {
                    check_digest(value, 16, errors);
                }
                if let Some(value) = database {
                    check_digest(value, 16, errors);
                }
                if let Some(value) = schema {
                    check_digest(value, 16, errors);
                }
                check_digest(table, 16, errors);
            }
            Self::DatabaseSchema {
                server,
                database,
                schema,
                ..
            } => {
                if let Some(value) = server {
                    check_digest(value, 16, errors);
                }
                if let Some(value) = database {
                    check_digest(value, 16, errors);
                }
                if let Some(value) = schema {
                    check_digest(value, 16, errors);
                }
            }
            Self::ObjectStore {
                scope, bucket, key, ..
            } => {
                scope.as_ref().check(errors);
                check_digest(bucket, 16, errors);
                if let Some(value) = key {
                    check_digest(value, 16, errors);
                }
            }
            Self::CloudResource { scope, id, .. } => {
                scope.as_ref().check(errors);
                if let Some(value) = id {
                    check_digest(value, 16, errors);
                }
            }
            Self::MessageTopic { scope, name, .. } => {
                scope.as_ref().check(errors);
                check_digest(name, 16, errors);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "expr", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceShape {
    Concrete {
        identity: ResourceShapeIdentity,
    },
    Literal {
        digest: String,
    },

    Parameter {
        name: String,
    },

    Environment {
        name: String,
    },

    Property {
        base: Box<ResourceShape>,
        name: String,
    },

    Join {
        parts: Vec<ResourceShape>,
    },

    Union {
        alternatives: Vec<ResourceShape>,
    },

    Pattern {
        family: ResourceFamily,
        digest: String,
    },

    Unresolved {
        family: ResourceFamily,
    },
}

impl ResourceShape {
    fn from(value: &ResourceExpr) -> Self {
        match value {
            ResourceExpr::Concrete { identity } => Self::Concrete {
                identity: ResourceShapeIdentity::from(identity),
            },
            ResourceExpr::Literal { value } => Self::Literal {
                digest: digest(value),
            },
            ResourceExpr::Parameter { name } => Self::Parameter { name: name.clone() },
            ResourceExpr::Environment { name } => Self::Environment { name: name.clone() },
            ResourceExpr::Property { base, name } => Self::Property {
                base: Box::new(ResourceShape::from(base.as_ref())),
                name: name.clone(),
            },
            ResourceExpr::Join { parts } => Self::Join {
                parts: parts.iter().map(ResourceShape::from).collect(),
            },
            ResourceExpr::Union { alternatives } => Self::Union {
                alternatives: alternatives.iter().map(ResourceShape::from).collect(),
            },
            ResourceExpr::Pattern { pattern } => Self::Pattern {
                family: pattern.family(),
                digest: digest(&crate::canonical_json(pattern)),
            },
            ResourceExpr::Unresolved { family } => Self::Unresolved {
                family: family.clone(),
            },
        }
    }
}

impl ResourceShape {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::Concrete { identity, .. } => {
                identity.check(errors);
            }
            Self::Literal { digest, .. } => {
                check_digest(digest, 16, errors);
            }
            Self::Parameter { .. } => {}
            Self::Environment { .. } => {}
            Self::Property { base, .. } => {
                base.as_ref().check(errors);
            }
            Self::Join { parts, .. } => {
                for value in parts {
                    value.check(errors);
                }
            }
            Self::Union { alternatives, .. } => {
                for value in alternatives {
                    value.check(errors);
                }
            }
            Self::Pattern { digest, .. } => {
                check_digest(digest, 16, errors);
            }
            Self::Unresolved { .. } => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "realm", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedRealm {
    #[default]
    Host,

    /// Keeps the container runtime only; the container name is not represented.
    Container {
        runtime: String,
    },

    Kubernetes {
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        pod: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        container: Option<String>,
    },

    Chroot {
        #[serde(skip_serializing_if = "Option::is_none")]
        host_root: Option<String>,
    },

    Remote {
        endpoint: String,
    },
}

impl RedactedRealm {
    fn from(value: &ExecutionRealm) -> Self {
        match value {
            ExecutionRealm::Container { runtime, .. } => Self::Container {
                runtime: runtime.clone(),
            },
            ExecutionRealm::Kubernetes {
                namespace,
                pod,
                container,
            } => Self::Kubernetes {
                namespace: namespace.as_ref().map(|value| digest(value)),
                pod: digest(pod),
                container: container.as_ref().map(|value| digest(value)),
            },
            ExecutionRealm::Chroot { host_root } => Self::Chroot {
                host_root: host_root.as_ref().map(|value| digest(value)),
            },
            ExecutionRealm::Remote { endpoint } => Self::Remote {
                endpoint: digest(endpoint),
            },
            ExecutionRealm::Host => Self::Host,
        }
    }
}

impl RedactedRealm {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::Container { .. } => {}
            Self::Kubernetes {
                namespace,
                pod,
                container,
                ..
            } => {
                if let Some(value) = namespace {
                    check_digest(value, 16, errors);
                }
                check_digest(pod, 16, errors);
                if let Some(value) = container {
                    check_digest(value, 16, errors);
                }
            }
            Self::Chroot { host_root, .. } => {
                if let Some(value) = host_root {
                    check_digest(value, 16, errors);
                }
            }
            Self::Remote { endpoint, .. } => {
                check_digest(endpoint, 16, errors);
            }
            Self::Host => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedExecutionStreamValue {
    pub value: ResourceShape,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}

impl RedactedExecutionStreamValue {
    fn from(value: &ExecutionStreamValue) -> Self {
        Self {
            value: ResourceShape::from(&value.value),
            provenance: value.provenance.clone(),
        }
    }
}

impl RedactedExecutionStreamValue {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        self.value.check(errors);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RedactedStreams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin: Option<ExecutionStreamRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_value: Option<RedactedExecutionStreamValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<ExecutionStreamRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<ExecutionStreamRef>,
}

impl RedactedStreams {
    fn from(value: &ExecutionStreams) -> Self {
        Self {
            stdin: value.stdin.clone(),
            stdin_value: value
                .stdin_value
                .as_ref()
                .map(RedactedExecutionStreamValue::from),
            stdout: value.stdout.clone(),
            stderr: value.stderr.clone(),
        }
    }
}

impl RedactedStreams {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        if let Some(value) = &self.stdin_value {
            value.check(errors);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedExecutionNode {
    pub subject: RedactedSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<BoundaryRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<ResourceShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<ResourceShape>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, Option<ResourceShape>>,
    #[serde(default)]
    pub streams: RedactedStreams,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<RedactedContainerStorage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_span: Option<ByteSpan>,
    pub realm: RedactedRealm,
    pub assurance: ExecutionAssurance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ProvenanceRef>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<RedactedExecutionInput>,
}

impl RedactedExecutionNode {
    fn from(value: &ExecutionNode) -> Self {
        Self {
            subject: RedactedSubject::from(&value.subject),
            boundary: value.boundary,
            argv: value.argv.iter().map(ResourceShape::from).collect(),
            cwd: value.cwd.as_ref().map(ResourceShape::from),
            environment: value
                .environment
                .iter()
                .map(|(key, value)| (key.clone(), value.as_ref().map(ResourceShape::from)))
                .collect(),
            streams: RedactedStreams::from(&value.streams),
            mounts: value
                .mounts
                .iter()
                .map(RedactedContainerStorage::from)
                .collect(),
            source_span: value.source_span,
            realm: RedactedRealm::from(&value.realm),
            assurance: value.assurance,
            evidence: value.evidence.clone(),
            input: value.input.as_ref().map(RedactedExecutionInput::from),
        }
    }
}

impl RedactedExecutionNode {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        self.subject.check(errors);
        for value in &self.argv {
            value.check(errors);
        }
        if let Some(value) = &self.cwd {
            value.check(errors);
        }
        for value in self.environment.values().flatten() {
            value.check(errors);
        }
        self.streams.check(errors);
        for value in &self.mounts {
            value.check(errors);
        }
        self.realm.check(errors);
        if let Some(value) = &self.input {
            value.check(errors);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedExecutionGraph {
    pub entry: ExecutionNodeRef,
    pub nodes: Vec<RedactedExecutionNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<ExecutionEdge>,
}

impl RedactedExecutionGraph {
    fn from(value: &ExecutionGraph) -> Self {
        Self {
            entry: value.entry,
            nodes: value
                .nodes
                .iter()
                .map(RedactedExecutionNode::from)
                .collect(),
            edges: value.edges.clone(),
        }
    }
}

impl RedactedExecutionGraph {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        for value in &self.nodes {
            value.check(errors);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedExecutionSelector {
    InvocationPath,
    Environment { variable: String },
    RuntimeOption { option: String },
    Dependency { specifier: String },
    SearchPath,
    Convention { name: String },
}

impl RedactedExecutionSelector {
    fn from(value: &ExecutionSelector) -> Self {
        match value {
            ExecutionSelector::Environment { variable } => Self::Environment {
                variable: variable.clone(),
            },
            ExecutionSelector::RuntimeOption { option } => Self::RuntimeOption {
                option: option.clone(),
            },
            ExecutionSelector::Dependency { specifier } => Self::Dependency {
                specifier: digest(specifier),
            },
            ExecutionSelector::Convention { name } => Self::Convention { name: name.clone() },
            ExecutionSelector::InvocationPath => Self::InvocationPath,
            ExecutionSelector::SearchPath => Self::SearchPath,
        }
    }
}

impl RedactedExecutionSelector {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::Environment { .. } => {}
            Self::RuntimeOption { .. } => {}
            Self::Dependency { specifier, .. } => {
                check_digest(specifier, 16, errors);
            }
            Self::Convention { .. } => {}
            Self::InvocationPath => {}
            Self::SearchPath => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedExecutionSelection {
    Direct {
        request: String,
    },
    Search {
        candidates: Vec<ResourceShape>,
        selected: Option<u32>,
    },
}

impl RedactedExecutionSelection {
    fn from(value: &ExecutionSelection) -> Self {
        match value {
            ExecutionSelection::Direct { request } => Self::Direct {
                request: digest(request),
            },
            ExecutionSelection::Search {
                candidates,
                selected,
            } => Self::Search {
                candidates: candidates.iter().map(ResourceShape::from).collect(),
                selected: selected.as_ref().map(|value| *value),
            },
        }
    }
}

impl RedactedExecutionSelection {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::Direct { request, .. } => {
                check_digest(request, 16, errors);
            }
            Self::Search { candidates, .. } => {
                for value in candidates {
                    value.check(errors);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedExecutionInput {
    pub role: ExecutionInputRole,
    pub phase: ExecutionPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<ResourceShape>,
    pub assurance: ExecutionAssurance,
    pub selector: RedactedExecutionSelector,
    pub requester: ExecutionNodeRef,
    pub requester_component: String,
    pub selection: RedactedExecutionSelection,
    pub content: ExecutionContent,
}

impl RedactedExecutionInput {
    fn from(value: &ExecutionInput) -> Self {
        Self {
            role: value.role,
            phase: value.phase,
            selected: value.selected.as_ref().map(ResourceShape::from),
            assurance: value.assurance,
            selector: RedactedExecutionSelector::from(&value.selector),
            requester: value.requester,
            requester_component: value.requester_component.clone(),
            selection: RedactedExecutionSelection::from(&value.selection),
            content: value.content.clone(),
        }
    }
}

impl RedactedExecutionInput {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        if let Some(value) = &self.selected {
            value.check(errors);
        }
        self.selector.check(errors);
        self.selection.check(errors);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedProvenanceKind {
    SourceInput {
        path: String,
        digest: String,
    },
    HostContext {
        name: String,
    },

    SourceSpan {
        start: u32,
        end: u32,
    },

    Argument {
        index: u32,
    },

    ToolArgument {
        name: String,
    },

    ModelApplication {
        model: String,
    },

    Execution {
        node: u32,
    },

    /// One host observation, with its paths digested. Kinds and refusal codes
    /// describe shape, not content, so they survive redaction intact.
    HostObservation {
        query: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entry_kind: Option<crate::PathKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        followed: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refusal: Option<String>,
        /// How many entries a listing answer holds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        listed_entries: Option<usize>,
    },
}

impl RedactedProvenanceKind {
    fn from(value: &ProvenanceKind) -> Self {
        match value {
            ProvenanceKind::SourceInput {
                path,
                digest: content_digest,
            } => Self::SourceInput {
                path: digest(path),
                digest: content_digest.clone(),
            },
            ProvenanceKind::HostContext { name } => Self::HostContext { name: name.clone() },
            ProvenanceKind::SourceSpan { start, end } => Self::SourceSpan {
                start: *start,
                end: *end,
            },
            ProvenanceKind::Argument { index } => Self::Argument { index: *index },
            ProvenanceKind::ToolArgument { name } => Self::ToolArgument { name: name.clone() },
            ProvenanceKind::ModelApplication { model } => Self::ModelApplication {
                model: model.clone(),
            },
            ProvenanceKind::Execution { node } => Self::Execution { node: *node },
            ProvenanceKind::HostObservation { query, outcome } => {
                let (crate::ObservationQuery::Path { path }
                | crate::ObservationQuery::Listing { path, .. }) = query;
                let (kind, followed, refusal, listed_entries) = match outcome {
                    crate::ObservationOutcome::Refused(refusal) => {
                        (None, None, Some(refusal.code().to_string()), None)
                    }
                    crate::ObservationOutcome::Path(fact) => (
                        Some(fact.kind),
                        fact.followed.known().map(|target| digest(&target.path)),
                        match &fact.followed {
                            crate::Fact::Unavailable(refusal) => Some(refusal.code().to_string()),
                            crate::Fact::Known(_) => None,
                        },
                        None,
                    ),
                    crate::ObservationOutcome::Listing(fact) => (
                        None,
                        Some(digest(&fact.directory)),
                        None,
                        Some(fact.entries.len()),
                    ),
                };
                Self::HostObservation {
                    query: digest(path),
                    entry_kind: kind,
                    followed,
                    refusal,
                    listed_entries,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedProvenanceNode {
    #[serde(flatten)]
    pub kind: RedactedProvenanceKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub antecedents: Vec<ProvenanceRef>,
}
impl<'de> Deserialize<'de> for RedactedProvenanceNode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub antecedents: Vec<ProvenanceRef>,
        }
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("expected node object"))?;
        let mut common = serde_json::Map::new();
        for key in ["antecedents"] {
            if let Some(value) = object.remove(key) {
                common.insert(key.into(), value);
            }
        }
        let common: Wire = serde_json::from_value(serde_json::Value::Object(common))
            .map_err(serde::de::Error::custom)?;
        let kind = serde_json::from_value::<RedactedProvenanceKind>(value)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            kind,
            antecedents: common.antecedents,
        })
    }
}

impl RedactedProvenanceNode {
    fn from(value: &ProvenanceNode) -> Self {
        Self {
            kind: RedactedProvenanceKind::from(&value.kind),
            antecedents: value.antecedents.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedOccurrenceKind {
    Value {
        value: ResourceShape,
    },
    Port {
        port: Port,
    },
    ResourceInteraction {
        operation: Operation,
        resource: ResourceShape,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        attributes: BTreeMap<String, AttrValue>,
    },
    Boundary {
        reason: BoundaryReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<String>,
    },
}

impl RedactedOccurrenceKind {
    fn from(value: &OccurrenceKind) -> Self {
        match value {
            OccurrenceKind::Value { value } => Self::Value {
                value: ResourceShape::from(value),
            },
            OccurrenceKind::Port { port } => Self::Port { port: port.clone() },
            OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                attributes,
            } => Self::ResourceInteraction {
                operation: operation.clone(),
                resource: ResourceShape::from(resource),
                attributes: redact_attributes(attributes),
            },
            OccurrenceKind::Boundary { reason, limit, .. } => Self::Boundary {
                reason: reason.clone(),
                limit: limit.clone(),
            },
        }
    }
}

impl RedactedOccurrenceKind {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        match self {
            Self::Value { value, .. } => {
                value.check(errors);
            }
            Self::Port { .. } => {}
            Self::ResourceInteraction {
                resource,
                attributes,
                ..
            } => {
                resource.check(errors);
                check_attributes(attributes, errors);
            }
            Self::Boundary { .. } => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedOccurrenceNode {
    pub id: OccurrenceId,
    #[serde(flatten)]
    pub occurrence: RedactedOccurrenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionNodeRef>,
    #[serde(default, skip_serializing_if = "RedactedRealm::is_host")]
    pub realm: RedactedRealm,
    pub modality: Modality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
    pub order: u32,
    pub cardinality: CausalCardinality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}
impl<'de> Deserialize<'de> for RedactedOccurrenceNode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            pub id: OccurrenceId,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub execution: Option<ExecutionNodeRef>,
            #[serde(default, skip_serializing_if = "RedactedRealm::is_host")]
            pub realm: RedactedRealm,
            pub modality: Modality,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub condition: Option<Condition>,
            pub order: u32,
            pub cardinality: CausalCardinality,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub provenance: Vec<ProvenanceRef>,
        }
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("expected node object"))?;
        let mut common = serde_json::Map::new();
        for key in [
            "id",
            "execution",
            "realm",
            "modality",
            "condition",
            "order",
            "cardinality",
            "provenance",
        ] {
            if let Some(value) = object.remove(key) {
                common.insert(key.into(), value);
            }
        }
        let common: Wire = serde_json::from_value(serde_json::Value::Object(common))
            .map_err(serde::de::Error::custom)?;
        let occurrence = serde_json::from_value::<RedactedOccurrenceKind>(value)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            occurrence,
            id: common.id,
            execution: common.execution,
            realm: common.realm,
            modality: common.modality,
            condition: common.condition,
            order: common.order,
            cardinality: common.cardinality,
            provenance: common.provenance,
        })
    }
}

impl RedactedOccurrenceNode {
    fn from(value: &OccurrenceNode) -> Self {
        Self {
            id: value.id.clone(),
            occurrence: RedactedOccurrenceKind::from(&value.occurrence),
            execution: value.execution,
            realm: RedactedRealm::from(&value.realm),
            modality: value.modality,
            condition: redact_condition(&value.condition),
            order: value.order,
            cardinality: value.cardinality,
            provenance: value.provenance.clone(),
        }
    }
}

impl RedactedOccurrenceNode {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        self.occurrence.check(errors);
        self.realm.check(errors);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedCausality {
    pub coverage: CoverageClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<RedactedCausalityGraph>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedCausalityGraph {
    pub nodes: Vec<RedactedOccurrenceNode>,
    pub edges: Vec<CausalEdge>,
}

impl RedactedCausality {
    fn from(value: &Causality) -> Self {
        Self {
            coverage: value.coverage.clone(),
            graph: value.graph.as_ref().map(|graph| RedactedCausalityGraph {
                nodes: graph
                    .nodes
                    .iter()
                    .map(RedactedOccurrenceNode::from)
                    .collect(),
                edges: graph
                    .edges
                    .iter()
                    .map(|edge| CausalEdge {
                        condition: redact_condition(&edge.condition),
                        ..edge.clone()
                    })
                    .collect(),
            }),
        }
    }

    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        if let Some(graph) = &self.graph {
            for value in &graph.nodes {
                value.check(errors);
            }
        }
    }
}

/// A boundary without its `scope` or `detail`: redacted plans cannot tell apart
/// boundaries that differ only in those fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedBoundary {
    pub reason: BoundaryReason,
    pub class: BoundaryClass,

    pub domains: Vec<Domain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_resource: Option<ResourceShape>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee: Option<CalleeReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
}

impl RedactedBoundary {
    fn from(value: &Boundary) -> Self {
        Self {
            reason: value.reason.clone(),
            class: value.class,
            domains: value.domains.clone(),
            affected_resource: value.affected_resource.as_ref().map(ResourceShape::from),
            callee: value.callee.clone(),
            provenance: value.provenance.clone(),
            limit: value.limit.clone(),
        }
    }
}

impl RedactedBoundary {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        if let Some(value) = &self.affected_resource {
            value.check(errors);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedPlan {
    pub schema: String,
    pub subject: RedactedSubject,
    pub analysis: Analysis,
    pub effects: Vec<RedactedEffect>,
    pub execution_graph: RedactedExecutionGraph,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<RedactedProvenanceNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<RedactedBoundary>,
    pub coverage: Coverage,

    pub causality: RedactedCausality,
}

impl RedactedPlan {
    fn from(value: &Plan) -> Self {
        Self {
            schema: REDACTED_SCHEMA_V1.to_string(),
            subject: RedactedSubject::from(&value.subject),
            analysis: value.analysis.clone(),
            effects: value.effects.iter().map(RedactedEffect::from).collect(),
            execution_graph: RedactedExecutionGraph::from(&value.execution_graph),
            provenance: value
                .provenance
                .iter()
                .map(RedactedProvenanceNode::from)
                .collect(),
            boundaries: value
                .boundaries
                .iter()
                .map(RedactedBoundary::from)
                .collect(),
            coverage: value.coverage.clone(),
            causality: RedactedCausality::from(&value.causality),
        }
    }
}

impl RedactedPlan {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        self.subject.check(errors);
        for value in &self.effects {
            value.check(errors);
        }
        self.execution_graph.check(errors);
        for value in &self.boundaries {
            value.check(errors);
        }
        self.causality.check(errors);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedEffect {
    pub id: EffectId,
    pub operation: Operation,
    pub resource: ResourceShape,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, AttrValue>,
    pub modality: Modality,
    pub request_assurance: RequestAssurance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,

    #[serde(default, skip_serializing_if = "RedactedRealm::is_host")]
    pub realm: RedactedRealm,

    pub execution: ExecutionNodeRef,

    pub provenance: Vec<ProvenanceRef>,
}

impl RedactedEffect {
    fn from(value: &Effect) -> Self {
        Self {
            id: value.id.clone(),
            operation: value.operation.clone(),
            resource: ResourceShape::from(&value.resource),
            attributes: redact_attributes(&value.attributes),
            modality: value.modality,
            request_assurance: value.request_assurance,
            condition: redact_condition(&value.condition),
            realm: RedactedRealm::from(&value.realm),
            execution: value.execution,
            provenance: value.provenance.clone(),
        }
    }
}

impl RedactedEffect {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        self.resource.check(errors);
        check_attributes(&self.attributes, errors);
        self.realm.check(errors);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedScopeEvidence {
    pub kind: ScopeEvidenceKind,
    pub value: ResourceShape,

    pub origin: Option<RedactedRealm>,
}

impl RedactedScopeEvidence {
    fn from(value: &ScopeEvidence) -> Self {
        Self {
            kind: value.kind,
            value: ResourceShape::from(&value.value),
            origin: value.origin.as_ref().map(RedactedRealm::from),
        }
    }
}

impl RedactedScopeEvidence {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        self.value.check(errors);
        if let Some(value) = &self.origin {
            value.check(errors);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedResourceScope {
    pub kind: NamespaceKind,
    pub identity: BTreeMap<ScopeDimension, ScopeValue<ResourceShape>>,
    pub access: Vec<RedactedScopeEvidence>,
}

impl RedactedResourceScope {
    fn from(value: &ResourceScope) -> Self {
        Self {
            kind: value.kind,
            identity: value
                .identity
                .iter()
                .map(|(key, value)| {
                    (
                        *key,
                        match value {
                            ScopeValue::Unknown => ScopeValue::Unknown,
                            ScopeValue::NotApplicable => ScopeValue::NotApplicable,
                            ScopeValue::Any => ScopeValue::Any,
                            ScopeValue::Value(value) => {
                                ScopeValue::Value(Box::new(ResourceShape::from(value.as_ref())))
                            }
                        },
                    )
                })
                .collect(),
            access: value
                .access
                .iter()
                .map(RedactedScopeEvidence::from)
                .collect(),
        }
    }
}

impl RedactedResourceScope {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        for value in self.identity.values() {
            if let ScopeValue::Value(value) = value {
                value.check(errors);
            }
        }
        for value in &self.access {
            value.check(errors);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedSubjectKind {
    Exec,
    Shell,
    Sql,
    Source,
    ToolCall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedSubject {
    pub kind: RedactedSubjectKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub digest: String,
}
impl RedactedSubject {
    fn from(value: &Subject) -> Self {
        let (kind, tool) = match value {
            Subject::Exec { .. } => (RedactedSubjectKind::Exec, None),
            Subject::Shell { .. } => (RedactedSubjectKind::Shell, None),
            Subject::Sql { .. } => (RedactedSubjectKind::Sql, None),
            Subject::Source { .. } => (RedactedSubjectKind::Source, None),
            Subject::ToolCall { call, .. } => {
                (RedactedSubjectKind::ToolCall, Some(call.name().to_string()))
            }
        };
        Self {
            kind,
            tool,
            digest: canonical_hash(value),
        }
    }
}
impl RedactedSubject {
    fn check(&self, errors: &mut Vec<RedactedValidationError>) {
        check_digest(&self.digest, 64, errors);
    }
}
impl RedactedRealm {
    pub fn is_host(&self) -> bool {
        matches!(self, Self::Host)
    }
}
fn redact_condition(condition: &Option<Condition>) -> Option<Condition> {
    condition.as_ref().map(Condition::redacted)
}

fn redact_attributes(attributes: &BTreeMap<String, AttrValue>) -> BTreeMap<String, AttrValue> {
    attributes
        .iter()
        .map(|(key, value)| (key.clone(), redact_attribute(value)))
        .collect()
}
fn redact_attribute(value: &AttrValue) -> AttrValue {
    match value {
        AttrValue::String(value) => AttrValue::String(digest(value)),
        AttrValue::List(values) => AttrValue::List(values.iter().map(redact_attribute).collect()),
        value => value.clone(),
    }
}
fn check_attributes(
    attributes: &BTreeMap<String, AttrValue>,
    errors: &mut Vec<RedactedValidationError>,
) {
    for value in attributes.values() {
        check_attribute(value, errors);
    }
}
fn check_attribute(value: &AttrValue, errors: &mut Vec<RedactedValidationError>) {
    match value {
        AttrValue::String(value) => check_digest(value, 16, errors),
        AttrValue::List(values) => {
            for value in values {
                check_attribute(value, errors);
            }
        }
        AttrValue::Bool(_) | AttrValue::Int(_) => {}
    }
}

/// Redact a plan into its redacted view: a pure, deterministic projection whose
/// literal digests correlate across plans.
///
/// Redaction limits. These stay visible in the output: environment-variable,
/// parameter, and property names; execution environment keys; a process
/// executable's basename; attribute keys and Boolean or integer attribute values
/// (only string attribute values, including list elements, are digested). The
/// projection is also lossy, so a redacted plan is not interchangeable with its
/// source: a container realm keeps its runtime but drops the container name,
/// and a boundary drops its scope and detail. The input is not validated here,
/// and [`validate_redacted`] checks only references and digest syntax, not that
/// retained fields are safe to share.
pub fn redact_plan(plan: &Plan) -> RedactedPlan {
    let mut view = RedactedPlan::from(plan);
    if !matches!(plan.subject, Subject::ToolCall { .. }) {
        for node in &mut view.provenance {
            if let RedactedProvenanceKind::ToolArgument { name } = &mut node.kind {
                *name = digest(name);
            }
        }
    }
    view
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedValidationError {
    pub context: String,
}
fn check_digest(value: &str, length: usize, errors: &mut Vec<RedactedValidationError>) {
    if !value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == length
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        errors.push(RedactedValidationError {
            context: "digest".into(),
        });
    }
}

/// Validates redacted references and digest syntax. Effect IDs cannot be recomputed
/// without the original literals; only conformance replay detects a well-formed substitution.
pub fn validate_redacted(view: &RedactedPlan) -> Result<(), Vec<RedactedValidationError>> {
    let mut errors = Vec::new();
    view.check(&mut errors);
    let mut require = |valid: bool, context: &str| {
        if !valid {
            errors.push(RedactedValidationError {
                context: context.into(),
            });
        }
    };
    require(view.schema == REDACTED_SCHEMA_V1, "schema");
    let executions = &view.execution_graph.nodes;
    let request_selections = crate::execution::exact_request_selections(
        executions.iter().map(|node| node.assurance),
        &view.execution_graph.edges,
    );
    let provenance_count = view.provenance.len();
    let refs_valid =
        |refs: &[ProvenanceRef]| refs.iter().all(|r| (r.0 as usize) < provenance_count);
    let condition_valid =
        |condition: &Option<Condition>| condition.as_ref().is_none_or(|c| c.is_redacted());
    let cardinality_valid = |modality, c: CausalCardinality| {
        c.max.is_none_or(|max| max > 0 && max >= c.min)
            && match modality {
                Modality::May => c.min == 0,
                Modality::MustOnSuccess => c.min > 0,
            }
    };
    let mut ids = BTreeSet::new();
    for effect in &view.effects {
        require(
            effect.request_assurance != RequestAssurance::Exact
                || (request_selections.get(effect.execution.0 as usize) == Some(&true)
                    && !effect.condition.as_ref().is_some_and(Condition::is_widened)
                    && effect.provenance.iter().any(|reference| {
                        view.provenance
                            .get(reference.0 as usize)
                            .is_some_and(|node| {
                                matches!(node.kind, RedactedProvenanceKind::ModelApplication { .. })
                            })
                    })),
            "effect.request_assurance",
        );
        require(
            effect.id.is_well_formed() && ids.insert(&effect.id),
            "effect.id",
        );
        require(
            executions
                .get(effect.execution.0 as usize)
                .is_some_and(|n| n.realm == effect.realm),
            "effect.execution",
        );
        require(refs_valid(&effect.provenance), "effect.provenance");
        require(condition_valid(&effect.condition), "effect.condition");
    }
    for (index, node) in view.provenance.iter().enumerate() {
        require(
            node.antecedents.iter().all(|r| (r.0 as usize) < index),
            "provenance.antecedents",
        );
        if let RedactedProvenanceKind::Execution { node } = node.kind {
            require((node as usize) < executions.len(), "provenance.execution");
        }
    }
    require(
        (view.execution_graph.entry.0 as usize) < executions.len(),
        "execution_graph.entry",
    );
    let mut incoming = vec![false; executions.len()];
    for (index, node) in executions.iter().enumerate() {
        require(
            node.boundary
                .is_none_or(|r| (r.0 as usize) < view.boundaries.len()),
            "execution.boundary",
        );
        require(refs_valid(&node.evidence), "execution.evidence");
        require(
            node.streams.stdin.is_none() || node.streams.stdin_value.is_none(),
            "execution.stdin",
        );
        if let Some(value) = &node.streams.stdin_value {
            require(refs_valid(&value.provenance), "stdin.provenance");
        }
        for stream in [
            &node.streams.stdin,
            &node.streams.stdout,
            &node.streams.stderr,
        ]
        .into_iter()
        .flatten()
        {
            require((stream.node.0 as usize) < executions.len(), "stream.node");
        }
        if let Some(input) = &node.input {
            require((input.requester.0 as usize) < index, "input.requester");
            if let RedactedExecutionSelection::Search {
                candidates,
                selected,
            } = &input.selection
            {
                require(
                    match selected {
                        Some(index) => candidates
                            .get(*index as usize)
                            .is_some_and(|c| Some(c) == input.selected.as_ref()),
                        None => input.selected.as_ref().is_none_or(|selected| {
                            input.assurance == crate::ExecutionAssurance::Alternatives
                                && candidates.contains(selected)
                        }),
                    },
                    "input.selection",
                );
            }
        }
    }
    for edge in &view.execution_graph.edges {
        require(
            (edge.from.0 as usize) < executions.len() && (edge.to.0 as usize) < executions.len(),
            "execution_edge.reference",
        );
        require(
            if edge.cycle {
                edge.to <= edge.from
            } else {
                edge.to > edge.from
            },
            "execution_edge.order",
        );
        require(refs_valid(&edge.evidence), "execution_edge.evidence");
        if let Some(incoming) = incoming.get_mut(edge.to.0 as usize) {
            *incoming = true;
        }
    }
    for (index, incoming) in incoming.into_iter().enumerate() {
        require(
            index == view.execution_graph.entry.0 as usize || incoming,
            "execution.incoming",
        );
    }
    for boundary in &view.boundaries {
        require(refs_valid(&boundary.provenance), "boundary.provenance");
    }
    for claim in view
        .coverage
        .0
        .values()
        .chain(std::iter::once(&view.causality.coverage))
    {
        require(
            claim
                .gaps
                .iter()
                .all(|r| (r.0 as usize) < view.boundaries.len()),
            "coverage.gaps",
        );
    }
    if let Some(graph) = &view.causality.graph {
        let mut occurrence_ids = BTreeSet::new();
        let mut resource_occurrences = BTreeSet::new();
        let mut widened_occurrences = BTreeSet::new();
        for (index, node) in graph.nodes.iter().enumerate() {
            require(occurrence_ids.insert(&node.id), "occurrence.id");
            if node.condition.as_ref().is_some_and(Condition::is_widened) {
                widened_occurrences.insert(&node.id);
            }
            if matches!(
                node.occurrence,
                RedactedOccurrenceKind::ResourceInteraction { .. }
            ) {
                resource_occurrences.insert(&node.id);
            }
            require(node.order as usize == index, "occurrence.order");
            require(
                cardinality_valid(node.modality, node.cardinality),
                "occurrence.cardinality",
            );
            require(condition_valid(&node.condition), "occurrence.condition");
            require(refs_valid(&node.provenance), "occurrence.provenance");
            require(
                node.execution.is_none_or(|r| {
                    executions
                        .get(r.0 as usize)
                        .is_some_and(|n| n.realm == node.realm)
                }),
                "occurrence.execution",
            );
        }
        for (index, edge) in graph.edges.iter().enumerate() {
            require(
                occurrence_ids.contains(&edge.from) && occurrence_ids.contains(&edge.to),
                "causal_edge.reference",
            );
            require(edge.order as usize == index, "causal_edge.order");
            require(
                edge.assurance != crate::CausalAssurance::Exact
                    || !(edge.condition.as_ref().is_some_and(Condition::is_widened)
                        || widened_occurrences.contains(&edge.from)
                        || widened_occurrences.contains(&edge.to)),
                "causal_edge.assurance",
            );
            require(
                edge.reason != CausalReason::ResourceTransfer
                    || (resource_occurrences.contains(&edge.from)
                        && resource_occurrences.contains(&edge.to)),
                "causal_edge.transfer_endpoint",
            );
            require(
                cardinality_valid(edge.modality, edge.cardinality),
                "causal_edge.cardinality",
            );
            require(condition_valid(&edge.condition), "causal_edge.condition");
            require(refs_valid(&edge.provenance), "causal_edge.provenance");
        }
    }
    for node in executions {
        if let Some(RedactedExecutionInput {
            content: ExecutionContent::Observed { digest } | ExecutionContent::Predicted { digest },
            ..
        }) = &node.input
        {
            check_digest(digest, 64, &mut errors);
        }
    }
    for node in &view.provenance {
        if let RedactedProvenanceKind::SourceInput { path, digest } = &node.kind {
            check_digest(path, 16, &mut errors);
            check_digest(digest, 64, &mut errors);
        }
    }
    if view.subject.kind != RedactedSubjectKind::ToolCall {
        for node in &view.provenance {
            if let RedactedProvenanceKind::ToolArgument { name } = &node.kind {
                check_digest(name, 16, &mut errors);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
