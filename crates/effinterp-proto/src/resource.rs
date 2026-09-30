use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// A resource family groups identities that share a namespace, e.g.
/// "filesystem" or "process". Families are open-ended strings so new domains
/// do not require a protocol revision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceFamily(pub Cow<'static, str>);

impl ResourceFamily {
    pub fn new(family: impl Into<String>) -> Self {
        Self(Cow::Owned(family.into()))
    }

    pub fn domain(&self) -> Option<&'static str> {
        FAMILY_DOMAINS
            .iter()
            .find(|(_, _, names)| names.contains(&self.0.as_ref()))
            .map(|(domain, _, _)| *domain)
    }
}

/// The path syntax used for lexical normalization. Normalization never reads
/// the host filesystem, so callers must name the syntax instead of inheriting
/// it from the machine running the analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPlatform {
    Posix,
    Windows,
}

pub(crate) const MAX_PROCESS_ARGV: usize = 64;

/// Storage made visible inside a container. Bind mounts retain both resource
/// expressions so a symbolic host path is not confused with the container
/// path. Named volumes remain distinct from host paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContainerStorage {
    BindMount {
        host_path: ResourceExpr,
        container_path: ResourceExpr,
        read_only: bool,
    },
    Volume {
        name: String,
        container_path: ResourceExpr,
    },
}

/// Map an effect-domain name to the short family token used by selectors
/// (`filesystem` -> `fs`). One definition shared by every renderer.
pub fn selector_family(domain: &str) -> &'static str {
    FAMILY_DOMAINS
        .iter()
        .find(|(_, _, names)| names.contains(&domain))
        .map_or("other", |(_, token, _)| *token)
}

const FAMILY_DOMAINS: &[(&str, &str, &[&str])] = &[
    ("artifact", "artifact", &["artifact"]),
    ("filesystem", "fs", &["filesystem", "fs"]),
    ("process", "proc", &["process", "proc"]),
    ("environment", "env", &["environment", "env"]),
    ("network", "net", &["network", "net"]),
    ("database", "db", &["database", "db"]),
    ("container", "container", &["container"]),
    ("git", "git", &["git"]),
    ("cloud", "cloud", &["cloud"]),
    ("cloud", "obj", &["object", "obj"]),
    ("messaging", "topic", &["messaging", "topic"]),
    ("credential", "cred", &["credential", "cred"]),
    ("system", "sys", &["system", "sys"]),
    ("system", "svc", &["svc"]),
    ("system", "job", &["job"]),
    ("system", "vol", &["vol"]),
    ("system", "blk", &["blk"]),
    ("system", "host", &["host"]),
];

/// Namespace evidence distinguishes cluster scope from an unresolved namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum KubernetesNamespace {
    Cluster,
    Namespaced { namespace: Box<ResourceExpr> },
    Unknown { namespace: Box<ResourceExpr> },
}

/// Remote artifact namespace, independent of the process executing publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactEcosystem {
    Oci,
    Npm,
    GithubRelease,
}

/// Whole-artifact scope is different from an unresolved version or tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactReference<T = ResourceExpr> {
    Version { value: T },
    Tag { value: T },
    Digest { value: T },
    Whole {},
}

impl<T> ArtifactReference<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Version { value } | Self::Tag { value } | Self::Digest { value } => Some(value),
            Self::Whole {} => None,
        }
    }
    pub fn value_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Version { value } | Self::Tag { value } | Self::Digest { value } => Some(value),
            Self::Whole {} => None,
        }
    }
    pub fn map<U>(&self, f: impl FnOnce(&T) -> U) -> ArtifactReference<U> {
        match self {
            Self::Version { value } => ArtifactReference::Version { value: f(value) },
            Self::Tag { value } => ArtifactReference::Tag { value: f(value) },
            Self::Digest { value } => ArtifactReference::Digest { value: f(value) },
            Self::Whole {} => ArtifactReference::Whole {},
        }
    }
}

/// A typed resource identity with explicit namespace uncertainty. Fields that
/// can remain symbolic use ResourceExpr rather than a rendered approximation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceIdentity {
    Artifact {
        ecosystem: ArtifactEcosystem,
        endpoint: Box<ResourceExpr>,
        name: Box<ResourceExpr>,
        reference: Box<ArtifactReference>,
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
        path: String,
    },
    /// The home directory the account database records for a named user, as
    /// shell `~name` expansion selects it.
    UserHome {
        user: String,
    },
    EnvironmentVariable {
        name: String,
    },
    /// A Git repository and, for path-scoped operations, a pathspec within it.
    /// At least one of `worktree` and `git_dir` must be present.
    GitRepository {
        #[serde(skip_serializing_if = "Option::is_none")]
        worktree: Option<Box<ResourceExpr>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        git_dir: Option<Box<ResourceExpr>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pathspec: Option<Box<ResourceExpr>>,
    },
    Process {
        executable: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// At most 64 entries after [`normalize_resource`]: a longer argv keeps
        /// its first 63 and ends with an unresolved `process` entry.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        argv: Vec<ResourceExpr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<Box<ResourceExpr>>,
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
    /// A container instance, e.g. a `docker exec` target.
    Container {
        runtime: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        storage: Vec<ContainerStorage>,
    },
    /// Kubernetes API identity; a context label is evidence, not a cluster ID.
    KubernetesResource {
        api_group: String,
        kind: String,
        name: Box<ResourceExpr>,
        namespace: KubernetesNamespace,
        server: Box<ResourceExpr>,
        context: Box<ResourceExpr>,
    },
    /// A configuration address, never a physical provider object ID.
    ManagedInfrastructure {
        tool: String,
        configuration_root: Box<ResourceExpr>,
        workspace: Box<ResourceExpr>,
        resource_type: Option<String>,
        address: Option<String>,
        instance: Box<ResourceExpr>,
    },
    /// A database table. Enclosing scope (server, database, schema) is
    /// retained when known so `public.users` on server A is not confused
    /// with the same name elsewhere.
    DatabaseTable {
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
        table: String,
    },
    /// A database schema or the database itself, for schema-level DDL.
    DatabaseSchema {
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
    },
    /// An object-store object or bucket (S3, GCS, Azure Blob). `key` None
    /// means the whole bucket.
    ObjectStore {
        scope: Box<crate::ResourceScope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        bucket: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
    /// A cloud resource such as a compute instance or managed database:
    /// `service` (ec2, rds, compute, ...), `kind` (instance, db, ...), `id`.
    /// `id` None is one resource of that kind whose name the invocation does
    /// not state, such as a name read from a file or chosen at a prompt.
    CloudResource {
        scope: Box<crate::ResourceScope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        service: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// A message queue or topic (Kafka topic, RabbitMQ queue, MQTT topic,
    /// Pub/Sub subject). `system` names the broker family when known.
    MessageTopic {
        scope: Box<crate::ResourceScope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        system: Option<String>,
        name: String,
    },
}

impl ResourceIdentity {
    /// Expression fields in infrastructure identities share traversal and substitution.
    pub fn infrastructure_values(&self) -> Vec<&ResourceExpr> {
        match self {
            Self::KubernetesResource {
                name,
                namespace,
                server,
                context,
                ..
            } => {
                let mut values = vec![name.as_ref(), server.as_ref(), context.as_ref()];
                if let KubernetesNamespace::Namespaced { namespace }
                | KubernetesNamespace::Unknown { namespace } = namespace
                {
                    values.push(namespace);
                }
                values
            }
            Self::ManagedInfrastructure {
                configuration_root,
                workspace,
                instance,
                ..
            } => vec![configuration_root, workspace, instance],
            _ => Vec::new(),
        }
    }

    pub fn infrastructure_values_mut(&mut self) -> Vec<&mut ResourceExpr> {
        match self {
            Self::KubernetesResource {
                name,
                namespace,
                server,
                context,
                ..
            } => {
                let mut values = vec![name.as_mut(), server.as_mut(), context.as_mut()];
                if let KubernetesNamespace::Namespaced { namespace }
                | KubernetesNamespace::Unknown { namespace } = namespace
                {
                    values.push(namespace);
                }
                values
            }
            Self::ManagedInfrastructure {
                configuration_root,
                workspace,
                instance,
                ..
            } => vec![configuration_root, workspace, instance],
            _ => Vec::new(),
        }
    }
}

/// A bounded expression tree describing an effect's target. Unresolvable
/// targets widen to `Pattern` or `Unresolved`; they never disappear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "expr", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceExpr {
    /// A typed identity; nested namespace fields may still be unknown.
    Concrete {
        identity: ResourceIdentity,
    },
    Literal {
        value: String,
    },
    /// A caller- or function-parameter reference.
    Parameter {
        name: String,
    },
    /// An environment variable reference.
    Environment {
        name: String,
    },
    /// Property selection on another expression, e.g. `tenant.id`.
    Property {
        base: Box<ResourceExpr>,
        name: String,
    },
    /// Path or identifier concatenation of the parts in order.
    Join {
        parts: Vec<ResourceExpr>,
    },
    /// Exactly one of a finite set of alternatives.
    Union {
        alternatives: Vec<ResourceExpr>,
    },
    /// A bounded pattern over a family, e.g. glob `/tmp/build-*`.
    Pattern {
        pattern: crate::ResourcePattern,
    },
    /// Known family, unknown identity.
    Unresolved {
        family: ResourceFamily,
    },
}

/// Pure canonicalization for the resource value language. Join fragments keep
/// their lexical path text until composition is complete; roots and typed
/// identity fields are normalized, and unions are sorted and deduplicated.
///
/// Process argv truncation: normalization is lossy for long command lines. A
/// process identity with more than 64 argv entries keeps its first 63 and ends
/// with an unresolved `process` entry, which relations report as
/// [`MatchReason::TruncatedArgv`](crate::MatchReason::TruncatedArgv). The exact tail is gone, so
/// processes differing only past that point share one normalized identity (and
/// effect ID); inspect the original arguments before normalizing if the tail
/// matters.
pub fn normalize_resource(expr: ResourceExpr, platform: PathPlatform) -> ResourceExpr {
    normalize_resource_context(expr, platform, false)
}

fn normalize_resource_context(
    expr: ResourceExpr,
    platform: PathPlatform,
    fragment: bool,
) -> ResourceExpr {
    match expr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { .. },
        } if fragment => expr,
        ResourceExpr::Concrete { identity } => ResourceExpr::Concrete {
            identity: normalize_identity(identity, platform),
        },
        ResourceExpr::Pattern {
            pattern: crate::ResourcePattern::FsPath { glob: pattern },
        } if !fragment => ResourceExpr::Pattern {
            pattern: crate::ResourcePattern::FsPath {
                glob: crate::glob::normalize_glob(&pattern),
            },
        },
        ResourceExpr::Property { base, name } => ResourceExpr::Property {
            base: Box::new(normalize_resource(*base, platform)),
            name,
        },
        ResourceExpr::Join { parts } => {
            let mut flat = Vec::new();
            for part in parts {
                match normalize_resource_context(part, platform, true) {
                    ResourceExpr::Join { parts } => flat.extend(parts),
                    part => flat.push(part),
                }
            }
            // Only the first pattern can have a literal parent prefix. Flatten the
            // whole join first so a nested tail cannot traverse an earlier wildcard.
            if !fragment && flat.len() > 1 {
                for index in 0..flat.len() {
                    match &flat[index] {
                        ResourceExpr::Pattern {
                            pattern: crate::ResourcePattern::FsPath { glob: pattern },
                        } => {
                            if let Some((path, tail)) = crate::glob::glob_parent_prefix(pattern) {
                                let tail = ResourceExpr::Pattern {
                                    pattern: crate::ResourcePattern::FsPath {
                                        glob: tail.to_string(),
                                    },
                                };
                                flat.splice(
                                    index..=index,
                                    [
                                        ResourceExpr::Concrete {
                                            identity: ResourceIdentity::FsPath { path },
                                        },
                                        tail,
                                    ],
                                );
                            }
                            break;
                        }
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. },
                        }
                        | ResourceExpr::Literal { .. }
                        | ResourceExpr::Environment { .. }
                        | ResourceExpr::Parameter { .. } => {}
                        _ => break,
                    }
                }
            }
            if flat.len() == 1 {
                normalize_resource_context(flat.pop().unwrap(), platform, fragment)
            } else if !fragment
                && flat.iter().any(|part| {
                    matches!(
                        part,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { .. }
                        }
                    )
                })
                && let Some(path) = fold_fs_join(&flat, platform)
            {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                }
            } else {
                ResourceExpr::Join { parts: flat }
            }
        }
        ResourceExpr::Union { alternatives } => {
            let mut flat = Vec::new();
            for alternative in alternatives {
                match normalize_resource_context(alternative, platform, fragment) {
                    ResourceExpr::Union { alternatives } => flat.extend(alternatives),
                    alternative => flat.push(alternative),
                }
            }
            flat.sort_by_key(stable_key);
            flat.dedup();
            if flat.len() == 1 {
                flat.pop().unwrap()
            } else {
                ResourceExpr::Union { alternatives: flat }
            }
        }
        other => other,
    }
}

pub(crate) fn normalize_identity(
    mut identity: ResourceIdentity,
    platform: PathPlatform,
) -> ResourceIdentity {
    for value in identity.infrastructure_values_mut() {
        *value = normalize_resource(value.clone(), platform);
    }
    if let Some(scope) = identity.scope_mut() {
        crate::normalize_scope(scope, platform);
    }
    match identity {
        ResourceIdentity::Artifact {
            ecosystem,
            endpoint,
            name,
            reference,
        } => {
            let mut endpoint = normalize_resource(*endpoint, platform);
            if ecosystem == ArtifactEcosystem::Oci
                && let ResourceExpr::Literal { value } = &mut endpoint
                && value == "index.docker.io"
            {
                *value = "docker.io".into();
            }
            ResourceIdentity::Artifact {
                ecosystem,
                endpoint: Box::new(endpoint),
                name: Box::new(normalize_resource(*name, platform)),
                reference: Box::new(
                    reference.map(|value| normalize_resource(value.clone(), platform)),
                ),
            }
        }
        ResourceIdentity::FsPath { path } => ResourceIdentity::FsPath {
            path: normalize_path(&path, platform),
        },
        ResourceIdentity::NetworkEndpoint {
            host,
            scheme,
            port,
            path,
        } => {
            let (user, address) = host
                .rsplit_once('@')
                .map_or((None, host.as_str()), |(u, h)| (Some(u), h));
            let address = if address.contains(':')
                && let Some((address, zone)) = address.split_once('%')
            {
                format!("{}%{zone}", address.to_ascii_lowercase())
            } else if address.contains(':') {
                address.to_ascii_lowercase()
            } else {
                let dns = address
                    .strip_suffix('.')
                    .filter(|name| !name.is_empty() && !name.ends_with('.'))
                    .unwrap_or(address);
                dns.to_ascii_lowercase()
            };
            ResourceIdentity::NetworkEndpoint {
                host: user.map_or_else(|| address.clone(), |user| format!("{user}@{address}")),
                scheme: scheme.map(|scheme| scheme.to_ascii_lowercase()),
                port,
                path,
            }
        }
        ResourceIdentity::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => ResourceIdentity::GitRepository {
            worktree: worktree.map(|expr| Box::new(normalize_resource(*expr, platform))),
            git_dir: git_dir.map(|expr| Box::new(normalize_resource(*expr, platform))),
            pathspec: pathspec.map(|expr| Box::new(normalize_resource(*expr, platform))),
        },
        ResourceIdentity::Process {
            executable,
            path,
            mut argv,
            cwd,
        } => {
            if argv.len() > MAX_PROCESS_ARGV {
                argv.truncate(MAX_PROCESS_ARGV - 1);
                argv.push(ResourceExpr::Unresolved {
                    family: ResourceFamily::new("process"),
                });
            }
            ResourceIdentity::Process {
                executable,
                path: path.map(|path| normalize_path(&path, platform)),
                argv: argv
                    .into_iter()
                    .map(|arg| normalize_resource(arg, platform))
                    .collect(),
                cwd: cwd.map(|cwd| Box::new(normalize_resource(*cwd, platform))),
            }
        }
        ResourceIdentity::Container {
            runtime,
            name,
            image,
            storage,
        } => {
            let mut storage: Vec<_> = storage
                .into_iter()
                .map(|storage| normalize_storage(storage, platform))
                .collect();
            storage.sort_by_key(stable_key);
            storage.dedup();
            let name = name.and_then(|name| {
                let trimmed = name.trim_start_matches('/');
                if trimmed.is_empty() {
                    nonempty(Some(name))
                } else {
                    Some(trimmed.to_string())
                }
            });
            ResourceIdentity::Container {
                runtime: normalize_container_runtime(&runtime),
                name,
                image: nonempty(image.map(|image| image.trim().to_string())),
                storage,
            }
        }
        ResourceIdentity::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => ResourceIdentity::DatabaseTable {
            server: normalized_server(server),
            database: nonempty(database),
            schema: nonempty(schema),
            table,
        },
        ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema,
        } => ResourceIdentity::DatabaseSchema {
            server: normalized_server(server),
            database: nonempty(database),
            schema: nonempty(schema),
        },
        other => other,
    }
}

/// Canonical runtime name shared by container resources and execution realms.
pub fn normalize_container_runtime(runtime: &str) -> String {
    let runtime = runtime
        .trim()
        .trim_end_matches("://")
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    runtime.strip_suffix(".exe").unwrap_or(&runtime).to_string()
}

fn normalize_storage(storage: ContainerStorage, platform: PathPlatform) -> ContainerStorage {
    match storage {
        ContainerStorage::BindMount {
            host_path,
            container_path,
            read_only,
        } => ContainerStorage::BindMount {
            host_path: normalize_resource(host_path, platform),
            container_path: normalize_resource(container_path, PathPlatform::Posix),
            read_only,
        },
        ContainerStorage::Volume {
            name,
            container_path,
        } => ContainerStorage::Volume {
            name,
            container_path: normalize_resource(container_path, PathPlatform::Posix),
        },
    }
}

fn normalized_server(server: Option<String>) -> Option<String> {
    nonempty(server.map(|server| server.trim().trim_end_matches('.').to_ascii_lowercase()))
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// Compose filesystem segments and verbatim text before lexical normalization.
/// Callers must establish filesystem typing before folding an all-Literal join.
pub fn fold_fs_join(parts: &[ResourceExpr], platform: PathPlatform) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    let mut joined = String::new();
    for part in parts {
        match part {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => {
                let separator = |c| c == '/' || platform == PathPlatform::Windows && c == '\\';
                if !joined.is_empty()
                    && !joined.ends_with(separator)
                    && !path.starts_with(separator)
                {
                    joined.push('/');
                }
                if !joined.is_empty() && joined.ends_with(separator) {
                    joined.push_str(path.trim_start_matches(separator));
                } else {
                    joined.push_str(path);
                }
            }
            ResourceExpr::Literal { value } => joined.push_str(value),
            _ => return None,
        }
    }
    Some(normalize_path(&joined, platform))
}

/// Lexically normalize a path without filesystem or symlink access.
pub fn normalize_path(path: &str, platform: PathPlatform) -> String {
    match platform {
        PathPlatform::Posix => normalize_slash_path(path, path.starts_with('/'), ""),
        PathPlatform::Windows => {
            let path = path.replace('\\', "/");
            if let Some(rest) = path.strip_prefix("//") {
                return normalize_slash_path(rest, true, "//");
            }
            let mut drive_path = path.as_str();
            while let Some(rest) = drive_path.strip_prefix("./") {
                drive_path = rest;
            }
            if let Some(path) = normalize_windows_drive(drive_path) {
                return path;
            }
            let path = normalize_slash_path(&path, path.starts_with('/'), "");
            normalize_windows_drive(&path).unwrap_or(path)
        }
    }
}

fn normalize_windows_drive(path: &str) -> Option<String> {
    path.as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':')
        .then(|| {
            let prefix = format!("{}:", path[..1].to_ascii_uppercase());
            let rest = &path[2..];
            normalize_slash_path(rest, rest.starts_with('/'), &prefix)
        })
}

fn normalize_slash_path(path: &str, absolute: bool, prefix: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." if segments.last().is_some_and(|segment| *segment != "..") => {
                segments.pop();
            }
            ".." if !absolute => segments.push(segment),
            ".." => {}
            segment => segments.push(segment),
        }
    }
    let body = segments.join("/");
    match (prefix, absolute, body.is_empty()) {
        ("//", _, true) => "//".to_string(),
        ("//", _, false) => format!("//{body}"),
        (prefix, true, true) => format!("{prefix}/"),
        (prefix, true, false) => format!("{prefix}/{body}"),
        ("", false, true) => ".".to_string(),
        (prefix, false, true) => prefix.to_string(),
        (prefix, false, false) => format!("{prefix}{body}"),
    }
}

pub fn is_absolute_path(path: &str, platform: PathPlatform) -> bool {
    match platform {
        PathPlatform::Posix => path.starts_with('/'),
        PathPlatform::Windows => {
            path.starts_with(['/', '\\'])
                || path
                    .as_bytes()
                    .get(1)
                    .is_some_and(|separator| *separator == b':')
                    && path
                        .as_bytes()
                        .get(2)
                        .is_some_and(|separator| matches!(separator, b'/' | b'\\'))
        }
    }
}

/// Construct an exact path when its base is known, otherwise retain the cwd
/// derivation as a join.
pub fn filesystem_path(
    path: impl Into<String>,
    cwd: Option<ResourceExpr>,
    platform: PathPlatform,
) -> ResourceExpr {
    let path = path.into();
    let leaf = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: normalize_path(&path, platform),
        },
    };
    if is_absolute_path(&path, platform) {
        leaf
    } else {
        normalize_resource(
            ResourceExpr::Join {
                parts: vec![
                    cwd.unwrap_or_else(|| ResourceExpr::Parameter {
                        name: "cwd".to_string(),
                    }),
                    leaf,
                ],
            },
            platform,
        )
    }
}

/// Stable display text. Concrete output uses the selector dialect, while
/// symbolic nodes remain visibly symbolic.
pub fn display_resource(expr: &ResourceExpr) -> String {
    display_resource_inner(expr, false)
}

/// Human display includes namespace uncertainty and labels access evidence separately.
pub fn display_resource_with_scope(expr: &ResourceExpr) -> String {
    display_resource_inner(expr, true)
}

fn display_resource_inner(expr: &ResourceExpr, include_scope: bool) -> String {
    let display = |expr: &ResourceExpr| display_resource_inner(expr, include_scope);
    match expr {
        ResourceExpr::Concrete { identity } => {
            let mut text = display_identity(identity);
            if let Some(scope) = identity.scope().filter(|_| include_scope) {
                text.push_str(&format!(" [{}]", display_scope(scope)));
            }
            text
        }
        ResourceExpr::Literal { value } => format!("{value:?}"),
        ResourceExpr::Parameter { name } => format!("<{name}>"),
        ResourceExpr::Environment { name } => format!("${name}"),
        ResourceExpr::Property { base, name } => format!("{}.{name}", display(base)),
        ResourceExpr::Join { parts } => format!(
            "join({})",
            parts.iter().map(display).collect::<Vec<_>>().join(", ")
        ),
        ResourceExpr::Union { alternatives } => format!(
            "one_of({})",
            alternatives
                .iter()
                .map(display)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ResourceExpr::Pattern { pattern } => pattern.to_string(),
        ResourceExpr::Unresolved { family } => format!("<{}:?>", selector_family(&family.0)),
    }
}

fn display_scope(scope: &crate::ResourceScope) -> String {
    use crate::ScopeValue;
    let mut fields = vec![format!("{:?}", scope.kind)];
    for (dimension, value) in &scope.identity {
        let value = match value {
            ScopeValue::NotApplicable => continue,
            ScopeValue::Unknown => "?".to_string(),
            ScopeValue::Any => "*".to_string(),
            ScopeValue::Value(value) => display_resource_with_scope(value),
        };
        fields.push(format!("{dimension:?}={value}"));
    }
    for evidence in &scope.access {
        let mut value = display_resource_with_scope(&evidence.value);
        if let Some(origin) = &evidence.origin {
            value.push_str(&format!(" @ {origin:?}"));
        }
        fields.push(format!("access.{:?}={value}", evidence.kind));
    }
    fields.join("; ")
}

pub fn display_identity(identity: &ResourceIdentity) -> String {
    match identity {
        ResourceIdentity::KubernetesResource {
            api_group,
            kind,
            name,
            namespace,
            server,
            context,
        } => format!(
            "container:kubernetes/{api_group}/{kind}/{} [{}; server={}; context={}]",
            display_resource(name),
            serde_json::to_string(namespace).unwrap(),
            display_resource(server),
            display_resource(context)
        ),
        ResourceIdentity::ManagedInfrastructure {
            tool,
            configuration_root,
            address,
            workspace,
            instance,
            ..
        } => format!(
            "cloud:managed/{tool}/{}/{} [workspace={}; instance={}]",
            display_resource(configuration_root),
            address.as_deref().unwrap_or("?"),
            display_resource(workspace),
            display_resource(instance)
        ),
        ResourceIdentity::ServiceUnit { name, .. } => format!("svc:{name}"),
        ResourceIdentity::ScheduledJob { scheduler, owner } => format!(
            "job:{scheduler}{}",
            owner.as_ref().map(|o| format!("@{o}")).unwrap_or_default()
        ),
        ResourceIdentity::StorageVolume { manager, name } => format!("vol:{manager}/{name}"),
        ResourceIdentity::BlockDevice { device } => format!("blk:{device}"),
        ResourceIdentity::CredentialStore {
            provider,
            store,
            path,
        } => {
            format!(
                "cred:{}",
                std::iter::once(provider.as_str())
                    .chain(store.as_deref())
                    .chain(path.as_deref())
                    .collect::<Vec<_>>()
                    .join("/")
            )
        }
        ResourceIdentity::HostSystem {} => "host:self".to_string(),
        ResourceIdentity::FsPath { path } => format!("fs:{path}"),
        ResourceIdentity::UserHome { user } => format!("fs:~{user}"),
        ResourceIdentity::EnvironmentVariable { name } => format!("env:{name}"),
        ResourceIdentity::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => format!(
            "git:worktree={};git_dir={};pathspec={}",
            json_option(&worktree.as_deref().map(display_resource)),
            json_option(&git_dir.as_deref().map(display_resource)),
            json_option(&pathspec.as_deref().map(display_resource))
        ),
        ResourceIdentity::Process {
            executable,
            argv,
            cwd,
            ..
        } => {
            let mut out = format!("proc:{executable}");
            if !argv.is_empty() {
                out.push_str(" [");
                out.push_str(
                    &argv
                        .iter()
                        .map(display_resource)
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                out.push(']');
            }
            if let Some(cwd) = cwd {
                out.push_str(" @ ");
                out.push_str(&display_resource(cwd));
            }
            out
        }
        ResourceIdentity::NetworkEndpoint {
            host,
            scheme,
            port,
            path,
        } => {
            let host = if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
                format!("[{host}]")
            } else {
                host.clone()
            };
            format!(
                "net:{}{host}{}{}",
                scheme
                    .as_deref()
                    .map(|scheme| format!("{scheme}://"))
                    .unwrap_or_default(),
                port.map(|port| format!(":{port}")).unwrap_or_default(),
                path.as_deref()
                    .map(|path| if path.starts_with('/') {
                        path.to_string()
                    } else {
                        format!("/{path}")
                    })
                    .unwrap_or_default()
            )
        }
        ResourceIdentity::Container {
            runtime,
            name,
            image,
            ..
        } => match (name.as_deref(), image.as_deref()) {
            (Some(name), Some(image)) => {
                format!("container:{runtime}:{name} [image={image}]")
            }
            (Some(identity), None) | (None, Some(identity)) => {
                format!("container:{runtime}:{identity}")
            }
            (None, None) => format!("container:{runtime}:?"),
        },
        ResourceIdentity::DatabaseTable {
            server,
            database,
            schema,
            table,
        } => format!(
            "db:server={};database={};schema={};table={}",
            json_option(server),
            json_option(database),
            json_option(schema),
            json_option(&Some(table.clone()))
        ),
        ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema,
        } => format!(
            "db:server={};database={};schema={};table={}",
            json_option(server),
            json_option(database),
            json_option(schema),
            json_option(&None)
        ),
        ResourceIdentity::ObjectStore { bucket, key, .. } => match key {
            Some(key) => format!("obj:{bucket}/{key}"),
            None => format!("obj:{bucket}"),
        },
        ResourceIdentity::CloudResource {
            service, kind, id, ..
        } => format!("cloud:{service}/{kind}/{}", id.as_deref().unwrap_or("?")),
        ResourceIdentity::Artifact {
            ecosystem,
            endpoint,
            name,
            reference,
        } => {
            let ecosystem = match ecosystem {
                ArtifactEcosystem::Oci => "oci",
                ArtifactEcosystem::Npm => "npm",
                ArtifactEcosystem::GithubRelease => "github-release",
            };
            let reference = match reference.as_ref() {
                ArtifactReference::Version { value } => {
                    format!("version={}", display_resource(value))
                }
                ArtifactReference::Tag { value } => format!("tag={}", display_resource(value)),
                ArtifactReference::Digest { value } => {
                    format!("digest={}", display_resource(value))
                }
                ArtifactReference::Whole {} => "whole".into(),
            };
            format!(
                "artifact:{ecosystem} endpoint={} name={} {reference}",
                display_resource(endpoint),
                display_resource(name),
            )
        }
        ResourceIdentity::MessageTopic { name, .. } => format!("topic:{name}"),
    }
}

pub fn identity_family(identity: &ResourceIdentity) -> &'static str {
    match identity {
        ResourceIdentity::Artifact { .. } => "artifact",
        ResourceIdentity::FsPath { .. } | ResourceIdentity::UserHome { .. } => "fs",
        ResourceIdentity::EnvironmentVariable { .. } => "env",
        ResourceIdentity::GitRepository { .. } => "git",
        ResourceIdentity::Process { .. } => "proc",
        ResourceIdentity::NetworkEndpoint { .. } => "net",
        ResourceIdentity::Container { .. } | ResourceIdentity::KubernetesResource { .. } => {
            "container"
        }
        ResourceIdentity::DatabaseTable { .. } | ResourceIdentity::DatabaseSchema { .. } => "db",
        ResourceIdentity::ObjectStore { .. } => "obj",
        ResourceIdentity::CloudResource { .. } | ResourceIdentity::ManagedInfrastructure { .. } => {
            "cloud"
        }
        ResourceIdentity::MessageTopic { .. } => "topic",
        ResourceIdentity::ServiceUnit { .. } => "svc",
        ResourceIdentity::ScheduledJob { .. } => "job",
        ResourceIdentity::StorageVolume { .. } => "vol",
        ResourceIdentity::BlockDevice { .. } => "blk",
        ResourceIdentity::CredentialStore { .. } => "cred",
        ResourceIdentity::HostSystem { .. } => "host",
    }
}

/// Derive the effect domain carried by a typed resource expression. Untyped
/// symbolic leaves are ignored when a containing expression has one coherent
/// typed family; conflicting typed families have no single domain.
pub fn resource_domain(expr: &ResourceExpr) -> Option<&'static str> {
    match expr {
        ResourceExpr::Concrete { identity } => {
            ResourceFamily::new(identity_family(identity)).domain()
        }
        ResourceExpr::Property { base, .. } => resource_domain(base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            let mut domains = parts.iter().filter_map(resource_domain);
            let domain = domains.next()?;
            domains
                .all(|candidate| candidate == domain)
                .then_some(domain)
        }
        ResourceExpr::Pattern { pattern } => pattern.family().domain(),
        ResourceExpr::Unresolved { family } => family.domain(),
        ResourceExpr::Literal { .. }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. } => None,
    }
}

fn stable_key<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("resource serialization")
}

fn json_option(value: &Option<String>) -> String {
    serde_json::to_string(value).expect("resource field serialization")
}
