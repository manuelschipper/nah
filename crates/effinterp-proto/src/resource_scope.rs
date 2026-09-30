use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ExecutionRealm, PathPlatform, ResourceExpr, ResourceIdentity, normalize_resource};

/// Namespace dimensions are identity evidence, never client configuration labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDimension {
    Partition,
    Account,
    Project,
    Subscription,
    Region,
    Zone,
    StorageAccount,
    ResourceGroup,
    Cluster,
    Namespace,
}

const DIMENSIONS: [ScopeDimension; 10] = [
    ScopeDimension::Partition,
    ScopeDimension::Account,
    ScopeDimension::Project,
    ScopeDimension::Subscription,
    ScopeDimension::Region,
    ScopeDimension::Zone,
    ScopeDimension::StorageAccount,
    ScopeDimension::ResourceGroup,
    ScopeDimension::Cluster,
    ScopeDimension::Namespace,
];

/// Any is a selector constraint only; it is invalid in stored resource evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ScopeValue<T = ResourceExpr> {
    Unknown,
    NotApplicable,
    Any,
    Value(Box<T>),
}

impl<T> ScopeValue<T> {
    pub fn value(value: T) -> Self {
        Self::Value(Box::new(value))
    }
}

/// Unsupported subtypes do not inherit a supported subtype's identity rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    S3Bucket,
    GcsBucket,
    AzureBlob,
    AwsRegional,
    GceZonal,
    GceRegional,
    AzureVm,
    KafkaTopic,
    RabbitQueue,
    MqttTopic,
    NatsSubject,
    RedisChannel,
    RedisKey,
    Unsupported,
}

impl NamespaceKind {
    fn dimensions(self) -> &'static [ScopeDimension] {
        use ScopeDimension::*;
        match self {
            Self::S3Bucket => &[Partition],
            Self::GcsBucket => &[],
            Self::AzureBlob => &[StorageAccount],
            Self::AwsRegional => &[Partition, Account, Region],
            Self::GceZonal => &[Project, Zone],
            Self::GceRegional => &[Project, Region],
            Self::AzureVm => &[Subscription, ResourceGroup],
            Self::RabbitQueue | Self::RedisKey => &[Cluster, Namespace],
            Self::KafkaTopic | Self::MqttTopic | Self::RedisChannel => &[Cluster],
            Self::NatsSubject => &[Cluster, Account],
            Self::Unsupported => &DIMENSIONS,
        }
    }
}

/// Access seeds and configuration labels cannot prove physical disjointness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeEvidenceKind {
    Endpoint,
    Seed,
    Node,
    Profile,
    Context,
    SubscriptionName,
    RequestRegion,
    ConfigurationFile,
    UnresolvedConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEvidence<T = ResourceExpr> {
    pub kind: ScopeEvidenceKind,
    pub value: T,
    /// Relative and loopback endpoints are relative to the invocation's realm.
    pub origin: Option<ExecutionRealm>,
}

/// A complete typed dimension inventory keeps missing and inapplicable distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScope<T = ResourceExpr> {
    pub kind: NamespaceKind,
    pub identity: BTreeMap<ScopeDimension, ScopeValue<T>>,
    pub access: Vec<ScopeEvidence<T>>,
}

impl<T> ResourceScope<T> {
    pub fn new(kind: NamespaceKind) -> Self {
        Self {
            kind,
            identity: DIMENSIONS
                .into_iter()
                .map(|dimension| {
                    let value = if kind.dimensions().contains(&dimension) {
                        ScopeValue::Unknown
                    } else {
                        ScopeValue::NotApplicable
                    };
                    (dimension, value)
                })
                .collect(),
            access: Vec::new(),
        }
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.identity
            .values()
            .filter_map(|v| match v {
                ScopeValue::Value(value) => Some(value.as_ref()),
                _ => None,
            })
            .chain(self.access.iter().map(|e| &e.value))
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.identity
            .values_mut()
            .filter_map(|v| match v {
                ScopeValue::Value(value) => Some(value.as_mut()),
                _ => None,
            })
            .chain(self.access.iter_mut().map(|e| &mut e.value))
    }

    pub fn map<U>(&self, mut f: impl FnMut(&T) -> U) -> ResourceScope<U> {
        ResourceScope {
            kind: self.kind,
            identity: self
                .identity
                .iter()
                .map(|(d, v)| {
                    (
                        *d,
                        match v {
                            ScopeValue::Unknown => ScopeValue::Unknown,
                            ScopeValue::NotApplicable => ScopeValue::NotApplicable,
                            ScopeValue::Any => ScopeValue::Any,
                            ScopeValue::Value(v) => ScopeValue::value(f(v)),
                        },
                    )
                })
                .collect(),
            access: self
                .access
                .iter()
                .map(|e| ScopeEvidence {
                    kind: e.kind,
                    value: f(&e.value),
                    origin: e.origin.clone(),
                })
                .collect(),
        }
    }

    pub fn valid_dimensions(&self, selector: bool) -> bool {
        self.identity.len() == DIMENSIONS.len()
            && DIMENSIONS.iter().all(|d| match self.identity.get(d) {
                Some(ScopeValue::Any) => selector,
                Some(ScopeValue::NotApplicable) => !self.kind.dimensions().contains(d),
                Some(ScopeValue::Unknown | ScopeValue::Value(_)) => {
                    self.kind.dimensions().contains(d)
                }
                None => false,
            })
    }
}

impl ResourceIdentity {
    pub fn scope(&self) -> Option<&ResourceScope> {
        match self {
            Self::ObjectStore { scope, .. }
            | Self::CloudResource { scope, .. }
            | Self::MessageTopic { scope, .. } => Some(scope),
            _ => None,
        }
    }

    pub fn scope_mut(&mut self) -> Option<&mut ResourceScope> {
        match self {
            Self::ObjectStore { scope, .. }
            | Self::CloudResource { scope, .. }
            | Self::MessageTopic { scope, .. } => Some(scope),
            _ => None,
        }
    }
}

pub fn object_scope(provider: Option<&str>) -> ResourceScope {
    ResourceScope::new(match provider {
        Some("aws") => NamespaceKind::S3Bucket,
        Some("gcp") => NamespaceKind::GcsBucket,
        Some("azure") => NamespaceKind::AzureBlob,
        _ => NamespaceKind::Unsupported,
    })
}

pub fn cloud_scope(provider: Option<&str>, service: &str, kind: &str) -> ResourceScope {
    ResourceScope::new(match (provider, service, kind) {
        (Some("aws"), "ec2", "instance") | (Some("aws"), "rds", "db") => NamespaceKind::AwsRegional,
        (Some("gcp"), "compute", "instance") => NamespaceKind::GceZonal,
        (Some("azure"), "vm", "instance") => NamespaceKind::AzureVm,
        _ => NamespaceKind::Unsupported,
    })
}

pub fn messaging_scope(system: Option<&str>) -> ResourceScope {
    ResourceScope::new(match system {
        Some("kafka") => NamespaceKind::KafkaTopic,
        Some("rabbitmq") => NamespaceKind::RabbitQueue,
        Some("mqtt") => NamespaceKind::MqttTopic,
        Some("nats") => NamespaceKind::NatsSubject,
        Some("redis") => NamespaceKind::RedisChannel,
        _ => NamespaceKind::Unsupported,
    })
}

pub fn normalize_scope(scope: &mut ResourceScope, platform: PathPlatform) {
    for value in scope.values_mut() {
        *value = normalize_resource(value.clone(), platform);
    }
    let mut access = Vec::new();
    for evidence in std::mem::take(&mut scope.access) {
        if matches!(
            evidence.kind,
            ScopeEvidenceKind::Endpoint | ScopeEvidenceKind::Seed
        ) {
            let values = match &evidence.value {
                ResourceExpr::Literal { value } if evidence.kind == ScopeEvidenceKind::Seed => {
                    value
                        .split(',')
                        .map(|value| ResourceExpr::Literal {
                            value: value.trim().into(),
                        })
                        .collect()
                }
                _ => vec![evidence.value.clone()],
            };
            for value in values {
                access.push(ScopeEvidence {
                    value: normalize_resource(normalize_scope_endpoint(value), platform),
                    ..evidence.clone()
                });
            }
        } else {
            let mut evidence = evidence;
            if evidence.kind == ScopeEvidenceKind::Node
                && let ResourceExpr::Literal { value } = &mut evidence.value
                && let Some((node, host)) = value.split_once('@')
            {
                *value = format!("{node}@{}", host.trim_end_matches('.').to_ascii_lowercase());
            }
            access.push(evidence);
        }
    }
    access.sort_by_cached_key(crate::canonical_json);
    access.dedup();
    scope.access = access;
}

fn normalize_scope_endpoint(value: ResourceExpr) -> ResourceExpr {
    let unknown = || ResourceExpr::Unresolved {
        family: crate::ResourceFamily::new("network"),
    };
    match value {
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives
                .into_iter()
                .map(normalize_scope_endpoint)
                .collect(),
        },
        // A partly symbolic authority cannot be safely split into credentials and host.
        ResourceExpr::Join { ref parts }
            if parts.iter().any(
                |part| matches!(part, ResourceExpr::Literal { value } if value.contains('@')),
            ) =>
        {
            unknown()
        }
        ResourceExpr::Literal { value } => {
            let (scheme, rest) = value
                .split_once("://")
                .map_or((None, value.as_str()), |(s, r)| (Some(s), r));
            if matches!(scheme, Some("file")) {
                return unknown();
            }
            let (authority, path) = rest.find(['/', '?', '#']).map_or((rest, None), |index| {
                (&rest[..index], Some(rest[index..].to_string()))
            });
            let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
                let Some((host, suffix)) = rest.split_once(']') else {
                    return unknown();
                };
                let port = if suffix.is_empty() {
                    None
                } else {
                    let Some(port) = suffix.strip_prefix(':').and_then(|p| p.parse::<u16>().ok())
                    else {
                        return unknown();
                    };
                    Some(port)
                };
                (host, port)
            } else if let Some((host, port)) = authority.rsplit_once(':') {
                let Ok(port) = port.parse::<u16>() else {
                    return unknown();
                };
                (host, Some(port))
            } else {
                (authority, None)
            };
            if host.is_empty() {
                return unknown();
            }
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: host.trim_end_matches('.').to_ascii_lowercase(),
                    scheme: scheme.map(str::to_ascii_lowercase),
                    port,
                    path,
                },
            }
        }
        ResourceExpr::Concrete {
            identity:
                ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme,
                    port,
                    path,
                },
        } => ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
                scheme: scheme.map(|s| s.to_ascii_lowercase()),
                port,
                path,
            },
        },
        other => other,
    }
}

/// Qualify connection-local evidence after an effect receives its execution realm.
pub fn qualify_scope_origin(expr: &mut ResourceExpr, realm: &ExecutionRealm) {
    match expr {
        ResourceExpr::Concrete { identity } => {
            if let Some(scope) = identity.scope_mut() {
                for evidence in &mut scope.access {
                    if evidence.origin.is_some() {
                        continue;
                    }
                    let local = match &evidence.value {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::NetworkEndpoint { host, .. },
                        } => host == "localhost" || host == "::1" || host.starts_with("127."),
                        ResourceExpr::Literal { value } => {
                            let host = value.rsplit('@').next().unwrap_or(value);
                            value.starts_with(['/', '.'])
                                || evidence.kind == ScopeEvidenceKind::Node
                                    && (host == "localhost"
                                        || host == "::1"
                                        || host.starts_with("127."))
                        }
                        _ => matches!(
                            evidence.kind,
                            ScopeEvidenceKind::Endpoint | ScopeEvidenceKind::Seed
                        ),
                    };
                    if local {
                        evidence.origin = Some(realm.clone());
                    }
                }
            }
        }
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            for part in parts {
                qualify_scope_origin(part, realm);
            }
        }
        _ => {}
    }
}

/// One comparison for namespace identity; connection evidence is never an ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMatch {
    None,
    Possible,
    Exact,
}

pub fn compare_scope(expected: &ResourceScope, actual: &ResourceScope) -> ScopeMatch {
    use ScopeMatch::*;
    if expected.kind != actual.kind
        && expected.kind != NamespaceKind::Unsupported
        && actual.kind != NamespaceKind::Unsupported
    {
        return None;
    }
    let mut result = if expected.kind == NamespaceKind::Unsupported
        || actual.kind == NamespaceKind::Unsupported
    {
        Possible
    } else {
        Exact
    };
    for dimension in DIMENSIONS {
        let matched = match (
            expected.identity.get(&dimension),
            actual.identity.get(&dimension),
        ) {
            (Some(ScopeValue::Any), _) => Exact,
            (Some(ScopeValue::NotApplicable), Some(ScopeValue::NotApplicable)) => Exact,
            (Some(ScopeValue::Value(a)), Some(ScopeValue::Value(b))) => compare_scope_expr(a, b),
            _ => Possible,
        };
        if matched == None {
            return None;
        }
        if matched == Possible {
            result = Possible;
        }
    }
    // Custom service endpoints may select a namespace outside the provider's namespace.
    if expected
        .access
        .iter()
        .chain(&actual.access)
        .any(|e| e.kind == ScopeEvidenceKind::Endpoint)
        && matches!(
            expected.kind,
            NamespaceKind::S3Bucket | NamespaceKind::AwsRegional
        )
    {
        result = Possible;
    }
    if actual.access.iter().any(|e| {
        matches!(
            e.kind,
            ScopeEvidenceKind::ConfigurationFile | ScopeEvidenceKind::UnresolvedConfiguration
        )
    }) {
        result = Possible;
    }
    result
}

fn compare_scope_expr(a: &ResourceExpr, b: &ResourceExpr) -> ScopeMatch {
    match (a, b) {
        (ResourceExpr::Literal { value: a }, ResourceExpr::Literal { value: b }) => {
            if a == b {
                ScopeMatch::Exact
            } else {
                ScopeMatch::None
            }
        }
        (ResourceExpr::Union { alternatives }, other)
        | (other, ResourceExpr::Union { alternatives }) => {
            if alternatives
                .iter()
                .all(|a| compare_scope_expr(a, other) == ScopeMatch::None)
            {
                ScopeMatch::None
            } else {
                ScopeMatch::Possible
            }
        }
        _ => ScopeMatch::Possible,
    }
}

pub fn compare_scoped_identity(
    expected: &ResourceIdentity,
    actual: &ResourceIdentity,
) -> Option<ScopeMatch> {
    let a = expected.scope()?;
    let b = actual.scope()?;
    let compatible = match (expected, actual) {
        (
            ResourceIdentity::ObjectStore {
                provider: ap,
                bucket: ab,
                key: ak,
                ..
            },
            ResourceIdentity::ObjectStore {
                provider: bp,
                bucket: bb,
                key: bk,
                ..
            },
        ) => ab == bb && ak == bk && !option_conflict(ap, bp),
        (
            ResourceIdentity::CloudResource {
                provider: ap,
                service: as_,
                kind: ak,
                id: ai,
                ..
            },
            ResourceIdentity::CloudResource {
                provider: bp,
                service: bs,
                kind: bk,
                id: bi,
                ..
            },
        ) => as_ == bs && ak == bk && !option_conflict(ai, bi) && !option_conflict(ap, bp),
        (
            ResourceIdentity::MessageTopic {
                system: ap,
                name: an,
                ..
            },
            ResourceIdentity::MessageTopic {
                system: bp,
                name: bn,
                ..
            },
        ) => an == bn && !option_conflict(ap, bp),
        _ => false,
    };
    let mut result = if compatible {
        compare_scope(a, b)
    } else {
        ScopeMatch::None
    };
    let partly_unknown = match (expected, actual) {
        (
            ResourceIdentity::ObjectStore { provider: a, .. },
            ResourceIdentity::ObjectStore { provider: b, .. },
        ) => a.is_none() || b.is_none(),
        // An unstated ID may name the other resource or another one.
        (
            ResourceIdentity::CloudResource {
                provider: a,
                id: ai,
                ..
            },
            ResourceIdentity::CloudResource {
                provider: b,
                id: bi,
                ..
            },
        ) => a.is_none() || b.is_none() || ai.is_none() || bi.is_none(),
        (
            ResourceIdentity::MessageTopic { system: a, .. },
            ResourceIdentity::MessageTopic { system: b, .. },
        ) => a.is_none() || b.is_none(),
        _ => false,
    };
    if partly_unknown && result == ScopeMatch::Exact {
        result = ScopeMatch::Possible;
    }
    Some(result)
}

fn option_conflict(a: &Option<String>, b: &Option<String>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a != b)
}

/// Access selection tests recorded endpoints, not all aliases of a physical resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSelection {
    Physical,
    Access,
}

pub(crate) fn valid_resource_scope(identity: &ResourceIdentity, selector: bool) -> bool {
    let Some(scope) = identity.scope() else {
        return true;
    };
    if !scope.valid_dimensions(selector) || scope.access.len() > 64 {
        return false;
    }
    let expected = match identity {
        ResourceIdentity::ObjectStore { provider, .. } => object_scope(provider.as_deref()).kind,
        ResourceIdentity::CloudResource {
            provider,
            service,
            kind,
            ..
        } => cloud_scope(provider.as_deref(), service, kind).kind,
        ResourceIdentity::MessageTopic { system, .. } => messaging_scope(system.as_deref()).kind,
        _ => unreachable!(),
    };
    if scope.kind != NamespaceKind::Unsupported
        && scope.kind != expected
        && !(expected == NamespaceKind::RedisChannel && scope.kind == NamespaceKind::RedisKey)
        && !(expected == NamespaceKind::GceZonal && scope.kind == NamespaceKind::GceRegional)
    {
        return false;
    }
    scope
        .identity
        .iter()
        .all(|(dimension, value)| scope.kind.valid_scope_value(*dimension, value))
}

impl NamespaceKind {
    /// Validate supplied literals without rejecting symbolic scope expressions.
    pub fn valid_scope_value(self, dimension: ScopeDimension, value: &ScopeValue) -> bool {
        fn valid_expr(kind: NamespaceKind, dimension: ScopeDimension, expr: &ResourceExpr) -> bool {
            match expr {
                ResourceExpr::Literal { value } => {
                    if dimension == ScopeDimension::Namespace {
                        kind != NamespaceKind::RedisKey || value.parse::<u32>().is_ok()
                    } else {
                        !value.is_empty()
                    }
                }
                ResourceExpr::Union { alternatives } => alternatives
                    .iter()
                    .all(|value| valid_expr(kind, dimension, value)),
                _ => true,
            }
        }
        match value {
            ScopeValue::Value(expr) => valid_expr(self, dimension, expr),
            _ => true,
        }
    }
}

/// Namespace diff keys omit access evidence while stored facts keep every occurrence.
pub fn namespace_resource(expr: &ResourceExpr) -> ResourceExpr {
    let mut result = expr.clone();
    match &mut result {
        ResourceExpr::Concrete { identity } => {
            if let Some(scope) = identity.scope_mut() {
                scope.access.clear();
            }
        }
        ResourceExpr::Property { base, .. } => **base = namespace_resource(base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            for part in parts {
                *part = namespace_resource(part);
            }
        }
        _ => {}
    }
    result
}
