//! Resource selectors for reverse queries: parse a `family:needle` selector
//! and lower it into the protocol evaluator.

use effinterp_proto::{ExecutionRealm, ResourceExpr, ResourceIdentity};

/// Which execution realm a reverse query targets. A resource path means
/// different things in different realms, so a host query must not be satisfied
/// by a container-realm effect. An unqualified selector defaults to `Host`.
///
/// The optional fields narrow a match: `Container { runtime: None }` matches a
/// container of that name under any runtime, while `Some(runtime)` requires the
/// runtime too. `Pod` narrows by namespace and container only when they are
/// given, so `pod:<pod>` still matches regardless of namespace/container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealmFilter {
    Host,
    Container {
        name: String,
        runtime: Option<String>,
    },
    Pod {
        namespace: Option<String>,
        pod: String,
        container: Option<String>,
    },
    Remote {
        endpoint: String,
    },
    Chroot,
    Any,
}

impl RealmFilter {
    /// Whether an effect's realm satisfies this filter.
    pub fn matches(&self, realm: &ExecutionRealm) -> bool {
        match self {
            RealmFilter::Any => true,
            RealmFilter::Host => matches!(realm, ExecutionRealm::Host),
            RealmFilter::Container { name, runtime } => match realm {
                ExecutionRealm::Container {
                    runtime: r,
                    name: n,
                } => n == name && runtime.as_ref().is_none_or(|want| want == r),
                _ => false,
            },
            RealmFilter::Pod {
                namespace,
                pod,
                container,
            } => match realm {
                ExecutionRealm::Kubernetes {
                    namespace: ns,
                    pod: p,
                    container: c,
                } => {
                    p == pod
                        && namespace
                            .as_ref()
                            .is_none_or(|want| Some(want) == ns.as_ref())
                        && container
                            .as_ref()
                            .is_none_or(|want| Some(want) == c.as_ref())
                }
                _ => false,
            },
            RealmFilter::Remote { endpoint } => {
                matches!(realm, ExecutionRealm::Remote { endpoint: e } if e == endpoint)
            }
            RealmFilter::Chroot => matches!(realm, ExecutionRealm::Chroot { .. }),
        }
    }

    pub fn render(&self) -> String {
        match self {
            RealmFilter::Host => "host".to_string(),
            RealmFilter::Container {
                name,
                runtime: None,
            } => format!("container:{name}"),
            RealmFilter::Container {
                name,
                runtime: Some(runtime),
            } => format!("container:{runtime}:{name}"),
            RealmFilter::Pod {
                namespace,
                pod,
                container,
            } => {
                let mut s = String::from("pod:");
                if let Some(ns) = namespace {
                    s.push_str(ns);
                    s.push(':');
                }
                s.push_str(pod);
                if let Some(c) = container {
                    s.push(':');
                    s.push_str(c);
                }
                s
            }
            RealmFilter::Remote { endpoint } => format!("remote:{endpoint}"),
            RealmFilter::Chroot => "chroot".to_string(),
            RealmFilter::Any => "any-realm".to_string(),
        }
    }
}

/// A parsed reverse-query selector, e.g. `db:public.users`, `fs:/etc/*`, with
/// an optional realm qualifier. Supported qualifiers (each followed by
/// `/family:needle`):
/// - `host/` — the host realm.
/// - `any-realm/` — any execution origin.
/// - `container:<name>/` — a container of that name under any runtime.
/// - `container:<runtime>:<name>/` — that name under a specific runtime.
/// - `pod:<pod>/` — a Kubernetes pod, any namespace/container.
/// - `pod:<namespace>:<pod>/` — that pod in a specific namespace.
/// - `pod:<namespace>:<pod>:<container>/` — additionally a specific container.
/// - `remote:<endpoint>/` — a remote host reached over the network.
/// - `chroot/` — under a changed filesystem root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSelector {
    pub realm: RealmFilter,
    pub family: String,
    pub needle: String,
}

impl ResourceSelector {
    pub fn parse(input: &str) -> Result<Self, String> {
        // A realm qualifier is a leading segment before the first `/` that is
        // itself not part of the `family:needle` (which uses `:` then a path).
        let (realm, rest) = split_realm(input)?;
        let (family, needle) = rest.split_once(':').ok_or_else(|| {
            format!("selector {rest:?} must be `family:value` (e.g. db:public.users)")
        })?;
        if family.is_empty() || needle.is_empty() {
            return Err(format!("selector {rest:?} has an empty family or value"));
        }
        if needle.starts_with('@') {
            let identity = identity_from_selector(needle)
                .or_else(|| scoped_selector_from_needle(needle).map(|s| s.identity));
            if identity
                .as_ref()
                .is_none_or(|i| effinterp_proto::identity_family(i) != family)
            {
                return Err("invalid structural resource selector".into());
            }
        }
        Ok(Self {
            // Absent an explicit qualifier, the default realm depends on whether
            // the family's identity is tied to execution location.
            realm: realm.unwrap_or_else(|| default_realm_for_family(family)),
            family: family.to_string(),
            needle: needle.to_string(),
        })
    }

    /// The effect domain this selector's family corresponds to. Used to decide
    /// whether an entrypoint's opaque boundary could hide a match: a boundary
    /// covering this domain means the resource cannot be excluded.
    pub fn domain(&self) -> &str {
        match self.family.as_str() {
            "cred" => "credential",
            "fs" => "filesystem",
            "proc" => "process",
            "net" => "network",
            "container" => "container",
            "db" => "database",
            "env" => "environment",
            "git" => "git",
            "artifact" => "artifact",
            "obj" | "cloud" => "cloud",
            "topic" => "messaging",
            "sys" | "svc" | "job" | "vol" | "blk" | "host" => "system",
            other => other,
        }
    }
}

/// Split an optional leading realm qualifier from a selector. A qualifier is a
/// leading segment ending at the first `/`, followed by a `family:needle`.
/// `container:x` without a trailing `/family:` is a plain container-resource
/// selector, not a realm — that ambiguity is resolved by requiring the
/// remainder to look like `family:needle`.
fn split_realm(input: &str) -> Result<(Option<RealmFilter>, &str), String> {
    if let Some(rest) = input.strip_prefix("host/") {
        return Ok((Some(RealmFilter::Host), rest));
    }
    if let Some(rest) = input.strip_prefix("any-realm/") {
        return Ok((Some(RealmFilter::Any), rest));
    }
    if let Some(rest) = input.strip_prefix("chroot/")
        && rest.contains(':')
    {
        return Ok((Some(RealmFilter::Chroot), rest));
    }
    if let Some(after) = input.strip_prefix("container:")
        && let Some(slash) = after.find('/')
    {
        let (qualifier, rest) = (&after[..slash], &after[slash + 1..]);
        if !qualifier.is_empty() && rest.contains(':') {
            // `runtime:name` narrows by runtime; a bare `name` matches any.
            let filter = match qualifier.split_once(':') {
                Some((runtime, name)) if !runtime.is_empty() && !name.is_empty() => {
                    RealmFilter::Container {
                        name: name.to_string(),
                        runtime: Some(runtime.to_string()),
                    }
                }
                _ => RealmFilter::Container {
                    name: qualifier.to_string(),
                    runtime: None,
                },
            };
            return Ok((Some(filter), rest));
        }
    }
    if let Some(after) = input.strip_prefix("pod:")
        && let Some(slash) = after.find('/')
    {
        let (qualifier, rest) = (&after[..slash], &after[slash + 1..]);
        if rest.contains(':')
            && let Some(filter) = parse_pod_qualifier(qualifier)
        {
            return Ok((Some(filter), rest));
        }
    }
    if let Some(after) = input.strip_prefix("remote:")
        && let Some(slash) = after.find('/')
    {
        let (endpoint, rest) = (&after[..slash], &after[slash + 1..]);
        if !endpoint.is_empty() && rest.contains(':') {
            return Ok((
                Some(RealmFilter::Remote {
                    endpoint: endpoint.to_string(),
                }),
                rest,
            ));
        }
    }
    // No explicit realm qualifier; the family decides the default.
    Ok((None, input))
}

/// Parse the `:`-separated fields of a `pod:` qualifier: `pod`, `namespace:pod`,
/// or `namespace:pod:container`. Any empty field or an unexpected field count
/// makes this not a pod realm qualifier.
fn parse_pod_qualifier(qualifier: &str) -> Option<RealmFilter> {
    let fields: Vec<&str> = qualifier.split(':').collect();
    if fields.iter().any(|f| f.is_empty()) {
        return None;
    }
    let (namespace, pod, container) = match fields.as_slice() {
        [pod] => (None, *pod, None),
        [namespace, pod] => (Some(*namespace), *pod, None),
        [namespace, pod, container] => (Some(*namespace), *pod, Some(*container)),
        _ => return None,
    };
    Some(RealmFilter::Pod {
        namespace: namespace.map(str::to_string),
        pod: pod.to_string(),
        container: container.map(str::to_string),
    })
}

/// The default execution-origin filter for an unqualified selector. A resource
/// whose identity is realm-relative (a filesystem path, a pid, an env var)
/// defaults to the host realm, since the same string names different things in
/// different realms. A globally-identified resource (a database table, a network
/// endpoint, a cloud/object-store/messaging resource) is the same resource
/// wherever execution originates, so an unqualified query spans every realm.
fn default_realm_for_family(family: &str) -> RealmFilter {
    match family {
        "db" | "net" | "cloud" | "obj" | "topic" | "artifact" | "cred" => RealmFilter::Any,
        _ => RealmFilter::Host,
    }
}

/// Short family code for an effect, preferring the concrete identity and
/// falling back to the operation domain for symbolic resources.
pub(crate) fn family(op_domain: &str, resource: &ResourceExpr) -> &'static str {
    typed_resource_family(resource).unwrap_or_else(|| domain_family(op_domain))
}

fn typed_resource_family(resource: &ResourceExpr) -> Option<&'static str> {
    match resource {
        ResourceExpr::Concrete { identity } => Some(effinterp_proto::identity_family(identity)),
        ResourceExpr::Property { base, .. } => typed_resource_family(base),
        ResourceExpr::Join { parts } => {
            let mut families = parts.iter().filter_map(typed_resource_family);
            let family = families.next()?;
            families.all(|other| other == family).then_some(family)
        }
        _ => None,
    }
}

fn domain_family(domain: &str) -> &'static str {
    effinterp_proto::selector_family(domain)
}

/// Lower a selector to typed protocol operands; unsupported families stay unknown.
impl ResourceSelector {
    pub fn scope_set(&self) -> Option<effinterp_proto::ScopeSet> {
        use effinterp_proto::{Field, PortField, ResourcePattern, ScopeSet, TextField};
        let n = &self.needle;
        if n.starts_with('@') {
            return identity_from_selector(n).map(|identity| ScopeSet::Exact { identity });
        }
        let field =
            |value: Option<String>| value.map_or(Field::Any, |value| Field::Exact { value });
        let pattern = match self.family.as_str() {
            "fs" => {
                if !n.contains(['*', '?', '[', '\\']) {
                    return Some(ScopeSet::FsSubtree { root: n.clone() });
                }
                ResourcePattern::FsPath {
                    glob: n.clone(),
                    narrowing: Default::default(),
                }
            }
            "env" => ResourcePattern::EnvironmentVariable {
                name_glob: n.clone(),
            },
            "proc" => ResourcePattern::Process {
                executable: if n.contains(['*', '?', '[', '\\']) {
                    TextField::Glob { glob: n.clone() }
                } else {
                    TextField::Exact { value: n.clone() }
                },
                argv_prefix: vec![],
            },
            "db" => {
                let parsed = if n.starts_with("server=") {
                    DatabaseIdentitySelector::parse(n)?
                } else {
                    let (schema, table) = n
                        .split_once('.')
                        .map_or((None, n.as_str()), |(schema, table)| {
                            (Some(schema.to_string()), table)
                        });
                    DatabaseIdentitySelector {
                        server: None,
                        database: None,
                        schema,
                        table: Some(table.to_string()),
                    }
                };
                match parsed.table {
                    Some(table) => ResourcePattern::DatabaseTable {
                        server: field(parsed.server),
                        database: field(parsed.database),
                        schema: field(parsed.schema),
                        table: if table == "*" {
                            Field::Any
                        } else {
                            field(Some(table))
                        },
                    },
                    None => ResourcePattern::DatabaseSchema {
                        server: field(parsed.server),
                        database: field(parsed.database),
                        schema: field(parsed.schema),
                    },
                }
            }
            "git" => {
                let parsed = if n.starts_with("worktree=") {
                    GitIdentitySelector::parse(n)?
                } else {
                    GitIdentitySelector {
                        worktree: Some(n.clone()),
                        git_dir: None,
                        pathspec: None,
                    }
                };
                ResourcePattern::GitRepository {
                    worktree: parsed
                        .worktree
                        .map(|s| s.strip_prefix("fs:").unwrap_or(&s).to_string()),
                    git_dir: parsed
                        .git_dir
                        .map(|s| s.strip_prefix("fs:").unwrap_or(&s).to_string()),
                    pathspec_glob: parsed
                        .pathspec
                        .map(|s| s.strip_prefix("fs:").unwrap_or(&s).to_string()),
                }
            }
            "net" => {
                let (scheme, rest) = n
                    .split_once("://")
                    .map_or((None, n.as_str()), |(scheme, rest)| {
                        (Some(scheme.to_string()), rest)
                    });
                let (authority, path) = rest.find('/').map_or((rest, None), |index| {
                    (&rest[..index], Some(rest[index..].to_string()))
                });
                let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
                    let (host, tail) = rest.split_once(']')?;
                    (
                        host,
                        if tail.is_empty() {
                            None
                        } else {
                            Some(tail.strip_prefix(':')?.parse().ok()?)
                        },
                    )
                } else if authority.matches(':').count() == 1 {
                    let (host, port) = authority.rsplit_once(':')?;
                    (host, Some(port.parse().ok()?))
                } else {
                    (authority, None)
                };
                ResourcePattern::NetworkEndpoint {
                    host_glob: host.into(),
                    scheme: field(scheme),
                    port: port.map_or(PortField::Any, |value| PortField::Exact { value }),
                    path_prefix: path,
                }
            }
            "obj" => {
                let (bucket, key) = n
                    .split_once('/')
                    .map_or((n.as_str(), None), |(bucket, key)| {
                        (bucket, Some(key.to_string()))
                    });
                ResourcePattern::ObjectStore {
                    provider: Field::Any,
                    bucket: bucket.into(),
                    key_prefix: key,
                }
            }
            "container" => {
                let (runtime, name) = n
                    .split_once(':')
                    .map_or((None, n.as_str()), |(runtime, name)| {
                        (Some(runtime.to_string()), name)
                    });
                ResourcePattern::Container {
                    runtime: field(runtime),
                    name_glob: Some(name.into()),
                    image_glob: None,
                }
            }
            "cloud" => {
                let parts: Vec<_> = n.splitn(3, '/').collect();
                let (service, kind, id) = if parts.len() == 3 {
                    (Some(parts[0].into()), Some(parts[1].into()), parts[2])
                } else {
                    (None, None, n.as_str())
                };
                ResourcePattern::CloudResource {
                    provider: Field::Any,
                    service: field(service),
                    kind: field(kind),
                    id_glob: id.into(),
                }
            }
            "topic" => ResourcePattern::MessageTopic {
                system: Field::Any,
                name_glob: n.clone(),
            },
            "svc" => ResourcePattern::ServiceUnit {
                manager: Field::Any,
                name_glob: n.clone(),
            },
            _ => return None,
        };
        Some(ScopeSet::Pattern { pattern })
    }

    pub fn match_effect(&self, fact: &effinterp_proto::EffectFact) -> effinterp_proto::Match {
        use effinterp_proto::{Bindings, EffectQuery, Match, MatchReason, PathPlatform, Scope};
        if self.domain() != fact.operation.domain() {
            return Match::NotSatisfied;
        }
        let realm = self.realm.evaluate(&fact.realm);
        if realm == Match::NotSatisfied {
            return realm;
        }
        let Some(set) = self.scope_set() else {
            return Match::Indeterminate {
                reason: MatchReason::UnsupportedShape,
            };
        };
        // Once the selection predicate accepts this realm, compare resources in it.
        let query = EffectQuery::Intersects {
            scope: Scope { realm: None, set },
        };
        let resource = query.evaluate(fact.into(), &Bindings::none(PathPlatform::Posix));
        match (realm, resource) {
            (_, Match::NotSatisfied) => Match::NotSatisfied,
            (unknown @ Match::Indeterminate { .. }, _) => unknown,
            (_, resource) => resource,
        }
    }
}
impl RealmFilter {
    pub fn evaluate(&self, realm: &ExecutionRealm) -> effinterp_proto::Match {
        use effinterp_proto::{Match, MatchReason, Proof};
        if let (
            Self::Pod {
                namespace,
                pod,
                container,
            },
            ExecutionRealm::Kubernetes {
                namespace: actual_namespace,
                pod: actual_pod,
                container: actual_container,
            },
        ) = (self, realm)
        {
            if pod != actual_pod
                || namespace
                    .as_ref()
                    .zip(actual_namespace.as_ref())
                    .is_some_and(|(a, b)| a != b)
                || container
                    .as_ref()
                    .zip(actual_container.as_ref())
                    .is_some_and(|(a, b)| a != b)
            {
                return Match::NotSatisfied;
            }
            if namespace.is_some() && actual_namespace.is_none()
                || container.is_some() && actual_container.is_none()
            {
                return Match::Indeterminate {
                    reason: MatchReason::UnderqualifiedRealm,
                };
            }
        }
        if self.matches(realm) {
            Match::Satisfied {
                proof: Proof { steps: vec![] },
            }
        } else {
            Match::NotSatisfied
        }
    }
}

/// The fixed, collision-free human selector form for a database identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseIdentitySelector {
    pub server: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
}

impl DatabaseIdentitySelector {
    pub fn parse(needle: &str) -> Option<Self> {
        let rest = needle.strip_prefix("server=")?;
        let (server, rest) = parse_json_option(rest)?;
        let rest = rest.strip_prefix(";database=")?;
        let (database, rest) = parse_json_option(rest)?;
        let rest = rest.strip_prefix(";schema=")?;
        let (schema, rest) = parse_json_option(rest)?;
        let rest = rest.strip_prefix(";table=")?;
        let (table, rest) = parse_json_option(rest)?;
        rest.is_empty().then_some(Self {
            server,
            database,
            schema,
            table,
        })
    }
}

/// The fixed human selector fields for a Git repository identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIdentitySelector {
    pub worktree: Option<String>,
    pub git_dir: Option<String>,
    pub pathspec: Option<String>,
}

impl GitIdentitySelector {
    pub fn parse(needle: &str) -> Option<Self> {
        let rest = needle.strip_prefix("worktree=")?;
        let (worktree, rest) = parse_json_option(rest)?;
        let rest = rest.strip_prefix(";git_dir=")?;
        let (git_dir, rest) = parse_json_option(rest)?;
        let rest = rest.strip_prefix(";pathspec=")?;
        let (pathspec, rest) = parse_json_option(rest)?;
        rest.is_empty().then_some(Self {
            worktree,
            git_dir,
            pathspec,
        })
    }
}

fn parse_json_option(input: &str) -> Option<(Option<String>, &str)> {
    if let Some(rest) = input.strip_prefix("null") {
        return Some((None, rest));
    }
    if !input.starts_with('"') {
        return None;
    }
    let mut escaped = false;
    for (offset, byte) in input.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            let end = offset + 1;
            let value = serde_json::from_str(&input[..end]).ok()?;
            return Some((Some(value), &input[end..]));
        }
    }
    None
}

/// Decode a typed `@<hex JSON identity>` selector needle. Human selector
/// needles return None and continue through family-specific matching.
pub fn identity_from_selector(needle: &str) -> Option<ResourceIdentity> {
    let bytes = hex_decode(needle.strip_prefix('@')?)?;
    effinterp_proto::reject_duplicate_keys(std::str::from_utf8(&bytes).ok()?).ok()?;
    let identity: ResourceIdentity = serde_json::from_slice(&bytes).ok()?;
    if !effinterp_proto::selector_identity_is_valid(&identity) {
        return None;
    }
    Some(identity)
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() > 131_072 || !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_value(pair[0])? << 4) | hex_value(pair[1])?))
        .collect()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeNeedle {
    #[serde(rename = "selection")]
    _selection: effinterp_proto::ScopeSelection,
    identity: ResourceIdentity,
}

fn scoped_selector_from_needle(needle: &str) -> Option<ScopeNeedle> {
    let bytes = hex_decode(needle.strip_prefix('@')?)?;
    effinterp_proto::reject_duplicate_keys(std::str::from_utf8(&bytes).ok()?).ok()?;
    let selector: ScopeNeedle = serde_json::from_slice(&bytes).ok()?;
    selector.identity.scope()?;
    effinterp_proto::selector_identity_is_valid(&selector.identity).then_some(selector)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_requires_family_and_value() {
        assert!(ResourceSelector::parse("db:public.users").is_ok());
        assert!(ResourceSelector::parse("nocolon").is_err());
        assert!(ResourceSelector::parse("fs:").is_err());
    }
}
