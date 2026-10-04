//! Which public resource an engine resource expression is: its identity,
//! selection and path labels, and the conversions of realm, domain, port and
//! condition that go with it.

use nah_proto::effects;
use nah_proto::effects::Knowledge::{Known, Unknown};
use std::collections::{BTreeMap, BTreeSet};

use super::invocation_calls::{add_gap, environmental_resource};

/// An effect's target resource, with the identity its attributes or a push's
/// aliased remote supply; the flag says the target is that aliased remote.
pub(super) fn effect_target_resource(
    view: &crate::plan_view::PlanView<'_>,
    graph: &mut effects::EffectGraph,
    effect: &effinterp_proto::Effect,
    effect_index: usize,
    member_effects: &[(usize, effinterp_proto::Effect)],
    effect_resources: &[effects::ResourceId],
) -> (effects::ResourceId, bool) {
    use effects::{ResourceDetails, ResourceIdentity, ResourceKind, Selection};
    let plan = view.plan();
    // The sync names this invocation's remote alias without resolving a
    // network host. A dry run has no audited request to carry that name.
    let remote = if effect.operation.as_str() == "network.upload"
        && matches!(&effect.resource, effinterp_proto::ResourceExpr::Unresolved { family } if family.0 == "network")
    {
        view.effects_exact("git.remote_sync").find_map(|sync| {
            (sync.execution == effect.execution
                && sync.realm == effect.realm
                && sync.condition == effect.condition
                && sync.operation.as_str() == "git.remote_sync"
                && sync.attributes.get("remote_complete")
                    == Some(&effinterp_proto::AttrValue::Bool(true)))
            .then(|| sync.attributes.get("remote"))
            .flatten()
            .and_then(|remote| match remote {
                effinterp_proto::AttrValue::String(alias) if !alias.is_empty() => {
                    Some(alias.clone())
                }
                _ => None,
            })
        })
    } else {
        None
    };
    let attributed = attributed_identity(view, effect);
    let aliased_remote = remote.is_some();
    let indexed_resource = (effect_index < plan.effects.len())
        .then(|| view.resource(view.effect_resource_id(effect_index)));
    let target = add_resource(
        graph,
        indexed_resource.map_or(&effect.resource, |resource| resource.expression),
        indexed_resource.map_or(&effect.realm, |resource| resource.realm),
        view.authority().platform(),
        remote.is_none() && attributed.is_none() && !environmental_resource(view, effect),
    );
    if let Some(identity) = attributed {
        let resource = &mut graph.resources[target.0 as usize];
        if identity.kind == ResourceKind::HostPath {
            resource.selection = Selection::Exact;
        }
        resource.identity = identity;
    }
    if let Some(alias) = remote {
        let resource = &mut graph.resources[target.0 as usize];
        resource.identity = ResourceIdentity {
            kind: ResourceKind::Endpoint,
            provider: Unknown,
            name: Known(alias),
            details: Known(ResourceDetails::Endpoint {
                host: Unknown,
                scheme: Unknown,
                port: Unknown,
                path: Unknown,
            }),
        };
        resource.selection = Selection::Exact;
    }
    if effect_index >= plan.effects.len() {
        let owner = member_effects[effect_index - plan.effects.len()].0;
        graph.resources[target.0 as usize].selection = graph.resources
            [effect_resources[owner].0 as usize]
            .selection
            .clone();
    }
    (target, aliased_remote)
}

/// Label an effect's host path target from its path annotation and the
/// observation of that path.
pub(super) fn label_effect_target_path(
    view: &crate::plan_view::PlanView<'_>,
    graph: &mut effects::EffectGraph,
    effect: &effinterp_proto::Effect,
    target: effects::ResourceId,
    annotation: nah_proto::effect_annotation::EffectAnnotation,
) {
    use effects::{Reach, ResourceKind, ResourceLabels};
    if (matches!(
        effect.resource,
        effinterp_proto::ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { .. }
        } | effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { .. }
        }
    ) || crate::observation_request::subtree_root(&effect.resource).is_some())
        && let Some(nah_proto::effect_annotation::PathLabel::Resolved {
            path,
            scope,
            sensitivity,
            protection,
            host_integrity,
            selects_root,
            selects_home,
        }) = annotation.path
    {
        // The engine spells a Windows pattern with `/`; the observed paths its
        // labels are compared with use the host's `\`. A bound spelled with
        // glob escapes is labeled as the directory it names, so the pattern
        // stays inside the project its observed bound belongs to.
        let pattern_path = match &effect.resource {
            effinterp_proto::ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { .. },
            } => crate::observation_request::observation_bound(&effect.resource).and_then(
                |(bound, tail)| {
                    let platform = view.authority().platform();
                    let glob = format!("{bound}{tail}");
                    let glob =
                        crate::observation_request::named_subset_reading(&effect.resource, &glob)
                            .unwrap_or(glob);
                    let glob = if platform == nah_proto::ctx::Platform::Windows {
                        glob.replace('/', "\\")
                    } else {
                        glob
                    };
                    nah_proto::ctx::AbsolutePath::new(platform, glob).ok()
                },
            ),
            _ => None,
        };
        let pattern = matches!(
            effect.resource,
            effinterp_proto::ResourceExpr::Pattern { .. }
        );
        // `BOUND/**/*` selects every entry below its bound except hidden
        // names, at every depth: the tree a recursive read of the bound
        // reaches, less its dotfiles. It selects the project, home or root its
        // observed bound is. A glob naming entries (`BOUND/**/target`) or
        // reaching fewer depths selects only part of its bound.
        let every_depth = selects_every_depth(&effect.resource);
        let home_reach = if pattern && !every_depth {
            if pattern_path.as_ref().is_some_and(|path| {
                nah_proto::labels::selects_home(
                    path.as_str(),
                    view.authority().home().as_str(),
                    view.authority().platform(),
                    true,
                )
            }) {
                Reach::Yes
            } else {
                Reach::Unknown
            }
        } else if selects_home {
            Reach::Yes
        } else if pattern {
            Reach::Unknown
        } else {
            Reach::No
        };
        graph.resources[target.0 as usize].labels = Some(ResourceLabels {
            lexical: if pattern {
                pattern_path.map_or(Unknown, Known)
            } else {
                Known(path.clone())
            },
            canonical: Unknown,
            scope: Known(scope),
            sensitivity: Known(sensitivity),
            protection: Known(protection),
            host_integrity: Known(host_integrity.into_iter().collect()),
            selects_project: if selects_root && (!pattern || every_depth) {
                Reach::Yes
            } else {
                Reach::Unknown
            },
            selects_home: home_reach,
            selects_root: if path.as_str() == "/" && (!pattern || every_depth) {
                Reach::Yes
            } else if pattern {
                Reach::Unknown
            } else {
                Reach::No
            },
            is_symlink: Unknown,
            link_target: Unknown,
            descendants_complete: Unknown,
            reach: vec![],
        });
    }
    if effect.realm.is_host()
        && graph.resources[target.0 as usize].identity.kind == ResourceKind::HostPath
    {
        let resource = &mut graph.resources[target.0 as usize];
        let labels = resource.labels.get_or_insert(ResourceLabels {
            lexical: Unknown,
            canonical: Unknown,
            scope: Unknown,
            sensitivity: Unknown,
            protection: Unknown,
            host_integrity: Unknown,
            selects_project: Reach::Unknown,
            selects_home: Reach::Unknown,
            selects_root: Reach::Unknown,
            is_symlink: Unknown,
            link_target: Unknown,
            descendants_complete: Unknown,
            reach: vec![],
        });
        labels.reach = selection_reach(view, effect);
        if labels.host_integrity == Unknown
            && let Some(class) = crate::annotate::lexical_host_integrity(
                effect,
                view.authority().home(),
                view.authority().platform(),
            )
        {
            labels.host_integrity = Known(vec![class]);
        }
        let exact_or_bounded_path = match &effect.resource {
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            resource => crate::observation_request::subtree_root(resource),
        };
        if let Some(value) = exact_or_bounded_path.and_then(|path| view.observed_path(path)) {
            labels.lexical = Known(value.resolved().clone());
            labels.canonical = value.realpath().cloned().map_or(Unknown, Known);
            labels.is_symlink = Known(value.kind() == nah_proto::observation::PathKind::Symlink);
            if value.kind() == nah_proto::observation::PathKind::Symlink {
                labels.link_target = labels.canonical.clone();
            }
            labels.descendants_complete =
                value.descendants().map_or(Unknown, |d| Known(d.complete()));
        }
    }
}

/// Whether a converted effect target still lacks the identity Nah decides on:
/// a kind that names nothing, or a kind whose details shape is missing and
/// whose selection does not itself describe what the effect reaches.
fn components_unavailable(
    identity: &effects::ResourceIdentity,
    selection: &effects::Selection,
) -> bool {
    // `Other` names a resource Nah's kind vocabulary has no word for, not one
    // whose identity is missing: it is a gap only when its components are
    // missing too, which the details clause already states.
    matches!(identity.kind, effects::ResourceKind::Unknown)
        || matches!(identity.details, Unknown)
            && !matches!(
                selection,
                effects::Selection::Pattern { .. } | effects::Selection::NamedSet { .. }
            )
}

/// Identify a registry effect's target from the components the engine states
/// as attributes.
///
/// A package client names the package, version, endpoint and selection scope
/// it acts on even where the plan leaves the resource expression unresolved,
/// and the physical publication or removal beside an audited request repeats
/// them. Components the operation has no form for stay unknown: an ownership
/// change names no version, and publication without manifest or archive bytes
/// names no package. `add_resource` decides completeness before any attribute
/// is read, so an identified target also retires the gap it recorded.
pub(super) fn identify_package_target(
    graph: &mut effects::EffectGraph,
    target: effects::ResourceId,
    package: effects::Knowledge<String>,
    version: effects::Knowledge<String>,
    registry: effects::Knowledge<String>,
    scope: effects::Knowledge<String>,
) {
    let resource = &mut graph.resources[target.0 as usize];
    if !components_unavailable(&resource.identity, &resource.selection) {
        return;
    }
    resource.identity.kind = effects::ResourceKind::Package;
    if let Known(package) = package {
        resource.identity.name = Known(package);
    }
    resource.identity.details = Known(effects::ResourceDetails::Package {
        version,
        // A registry alias names configuration still to be resolved, so only a
        // stated URL is the endpoint the operation reaches.
        registry,
    });
    resource.selection = match scope {
        Known(scope) if scope == "whole" => effects::Selection::Whole,
        Known(scope) if scope == "version" => effects::Selection::Exact,
        _ => resource.selection.clone(),
    };
    if let Some(index) = graph
        .gaps
        .iter()
        .rposition(|gap| gap.code == "resource-components-unavailable")
    {
        graph.gaps.remove(index);
    }
}

/// Recover identities that the resource expression cannot directly name.
/// Some effects are attributed by their attributes or a declaration emitted
/// beside them, while a HOME-relative join can be resolved from Nah's context.
fn attributed_identity(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
) -> Option<effects::ResourceIdentity> {
    if effect.operation.domain() == "filesystem"
        && let effinterp_proto::ResourceExpr::Join { parts } = &effect.resource
    {
        let mut joined = String::new();
        for part in parts {
            match part {
                effinterp_proto::ResourceExpr::Literal { value }
                | effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: value },
                } => joined.push_str(value),
                effinterp_proto::ResourceExpr::Environment { name } if name == "HOME" => {
                    joined.push_str(view.authority().home().as_str());
                }
                _ => return None,
            }
        }
        let path = nah_proto::ctx::AbsolutePath::new(view.authority().platform(), joined).ok()?;
        return Some(effects::ResourceIdentity {
            kind: effects::ResourceKind::HostPath,
            provider: Unknown,
            name: Known(path.as_str().to_owned()),
            details: Known(effects::ResourceDetails::Path {
                lexical: Known(path),
            }),
        });
    }
    if !matches!(
        effect.resource,
        effinterp_proto::ResourceExpr::Unresolved { .. }
    ) {
        return None;
    }
    let text = |key: &str| match effect.attributes.get(key) {
        Some(effinterp_proto::AttrValue::String(value)) if !value.is_empty() => {
            Known(value.clone())
        }
        _ => Unknown,
    };
    match effect.operation.as_str() {
        "container.remove" | "container.stop" if text("scope") == Known("compose".into()) => {
            let runtime = text("runtime");
            Some(effects::ResourceIdentity {
                kind: effects::ResourceKind::ContainerResource,
                provider: runtime.clone(),
                // A Compose service is a declaration, not a container name.
                name: Unknown,
                details: Known(effects::ResourceDetails::Container {
                    runtime,
                    namespace: text("project"),
                    volume: Unknown,
                }),
            })
        }
        // Terraform and OpenTofu carry a typed managed-stack resource instead
        // and state no provider attribute, so they keep their own identity.
        "cloud.resource.delete" if text("mode") == Known("destroy".into()) => {
            let tool = text("provider");
            matches!(tool, Known(_)).then(|| effects::ResourceIdentity {
                kind: effects::ResourceKind::ManagedInfrastructure,
                provider: tool,
                name: text("stack"),
                details: Known(effects::ResourceDetails::Infrastructure {
                    namespace: Unknown,
                    cluster: Unknown,
                    // A selected URN is a stack-relative address, not a
                    // provider object ID.
                    address: text("target"),
                }),
            })
        }
        "network.delete_request" if matches!(text("hosted_target_kind"), Known(ref kind) if kind == "repository" || kind == "resource") =>
        {
            let repository = text("hosted_target_kind") == Known("repository".into());
            let target = text("hosted_target");
            Some(effects::ResourceIdentity {
                kind: if repository {
                    effects::ResourceKind::HostedRepository
                } else {
                    effects::ResourceKind::HostedResource
                },
                provider: text("hosted_provider"),
                name: target.clone(),
                details: Known(effects::ResourceDetails::Hosted {
                    repository: if repository { target.clone() } else { Unknown },
                    object_kind: text("hosted_object_kind"),
                    object: if repository { Unknown } else { target },
                }),
            })
        }
        // The transport a cloud or secret-manager client opens to reach its
        // service. The engine states the connection but no endpoint, because
        // the service host comes from that client's own environment, and it
        // names the provider on the modeled cloud or credential effect the
        // same execution emits beside it. That provider is this connection's
        // counterpart, exactly as a push's audited remote names the alias
        // behind an unresolved upload.
        _ if effect.operation.domain() == "network"
            && matches!(&effect.resource, effinterp_proto::ResourceExpr::Unresolved { family } if family.0 == "network") =>
        {
            let provider = view
                .effects_for_execution(effect.execution)
                .find_map(|peer| {
                    if peer.realm != effect.realm || peer.condition != effect.condition {
                        return None;
                    }
                    match &peer.resource {
                        effinterp_proto::ResourceExpr::Concrete {
                            identity:
                                effinterp_proto::ResourceIdentity::ObjectStore { provider, .. }
                                | effinterp_proto::ResourceIdentity::CloudResource { provider, .. },
                        } => provider.clone(),
                        effinterp_proto::ResourceExpr::Concrete {
                            identity:
                                effinterp_proto::ResourceIdentity::CredentialStore { provider, .. },
                        } => Some(provider.clone()),
                        _ => None,
                    }
                });
            let protocol = text("protocol");
            let port = match text("port") {
                Known(port) => port.parse::<u16>().ok().map_or(Unknown, Known),
                Unknown => Unknown,
            };
            let host = text("host");
            let path = text("path");
            if provider.is_none()
                && host == Unknown
                && protocol == Unknown
                && port == Unknown
                && path == Unknown
            {
                None
            } else {
                Some(effects::ResourceIdentity {
                    kind: effects::ResourceKind::Endpoint,
                    provider: provider.map_or(Unknown, Known),
                    name: host.clone(),
                    details: Known(effects::ResourceDetails::Endpoint {
                        host,
                        scheme: protocol,
                        port,
                        path,
                    }),
                })
            }
        }
        _ => None,
    }
}

/// The storage subject a managed cloud resource's deletion destroys, or
/// `None` when its kind names no storage the storage guards decide on.
fn cloud_storage_target(service: &str, kind: &str) -> Option<effects::StorageTarget> {
    match kind {
        "snapshot" | "snapshots" => Some(effects::StorageTarget::Snapshot),
        "volume" | "volumes" | "disk" | "disks" => Some(effects::StorageTarget::LiveVolume),
        "account" if service == "storage" => Some(effects::StorageTarget::ObjectTree),
        _ => None,
    }
}
/// Nah's effect domain for an engine operation domain.
pub(super) fn convert_domain(domain: &str) -> effects::Domain {
    match domain {
        "filesystem" => effects::Domain::Filesystem,
        "process" => effects::Domain::Process,
        "network" => effects::Domain::Network,
        "environment" => effects::Domain::Environment,
        "git" => effects::Domain::Git,
        "credential" => effects::Domain::Credential,
        "container" => effects::Domain::Container,
        "cloud" => effects::Domain::Infrastructure,
        "system" => effects::Domain::System,
        "artifact" => effects::Domain::Package,
        "database" => effects::Domain::Database,
        "messaging" => effects::Domain::Messaging,
        _ => effects::Domain::Other,
    }
}
/// Nah's realm for an engine execution realm.
pub(super) fn convert_realm(realm: &effinterp_proto::ExecutionRealm) -> effects::Realm {
    match realm {
        effinterp_proto::ExecutionRealm::Host => effects::Realm::Host,
        effinterp_proto::ExecutionRealm::Remote { endpoint } => effects::Realm::Remote {
            identity: Known(endpoint.clone()),
        },
        effinterp_proto::ExecutionRealm::Container { runtime, name } => effects::Realm::Container {
            identity: Known(format!("{runtime}:{name}")),
        },
        effinterp_proto::ExecutionRealm::Kubernetes { .. } => {
            effects::Realm::Container { identity: Unknown }
        }
        effinterp_proto::ExecutionRealm::Chroot { .. } => effects::Realm::Unknown,
    }
}
/// Nah's modality for an engine effect modality.
pub(super) fn convert_modality(modality: effinterp_proto::Modality) -> effects::Modality {
    match modality {
        effinterp_proto::Modality::May => effects::Modality::May,
        effinterp_proto::Modality::MustOnSuccess => effects::Modality::MustOnSuccess,
    }
}
/// Nah's port kind for an engine causality port.
pub(super) fn convert_port(port: &effinterp_proto::Port) -> effects::PortKind {
    use effects::PortKind;
    match port {
        effinterp_proto::Port::Stdin => PortKind::Stdin,
        effinterp_proto::Port::Stdout => PortKind::Stdout,
        effinterp_proto::Port::Stderr => PortKind::Stderr,
        effinterp_proto::Port::Code => PortKind::Code,
        effinterp_proto::Port::Arg(_) => PortKind::Argument,
        effinterp_proto::Port::HttpRequestBody => PortKind::NetworkRequest,
        effinterp_proto::Port::HttpResponseBody => PortKind::NetworkResponse,
        effinterp_proto::Port::ArchiveInput => PortKind::ArchiveInput,
        effinterp_proto::Port::ArchiveOutput => PortKind::ArchiveOutput,
        _ => PortKind::Value,
    }
}

/// Convert one engine resource expression into a public resource.
///
/// `effect_target` says the expression is what an effect acts on, so failing to
/// identify it is a translation gap. A causal value node carries no resource
/// identity to begin with, and reporting one as missing would leave every
/// command permanently short of full coverage.
pub(super) fn add_resource(
    graph: &mut effects::EffectGraph,
    resource: &effinterp_proto::ResourceExpr,
    realm: &effinterp_proto::ExecutionRealm,
    platform: nah_proto::ctx::Platform,
    effect_target: bool,
) -> effects::ResourceId {
    use effects::{ResourceDetails, ResourceKind, Selection};
    let mut identity = effects::ResourceIdentity {
        kind: ResourceKind::Unknown,
        name: Unknown,
        provider: Unknown,
        details: Unknown,
    };
    let mut selection = Selection::Unknown;
    // Set by an arm that carries a typed identity the engine left incomplete,
    // where the missing component is the target's own and not the environment's.
    let mut incomplete_identity = false;
    let text = |value: &effinterp_proto::ResourceExpr| match value {
        effinterp_proto::ResourceExpr::Literal { value } => Known(value.clone()),
        effinterp_proto::ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } => Known(path.clone()),
        _ => Unknown,
    };
    let path = |value: &effinterp_proto::ResourceExpr| match text(value) {
        Known(value) => nah_proto::ctx::AbsolutePath::new(platform, value)
            .ok()
            .map_or(Unknown, Known),
        Unknown => Unknown,
    };
    match resource {
        effinterp_proto::ResourceExpr::Concrete { identity: source } => {
            selection = Selection::Exact;
            match source {
                effinterp_proto::ResourceIdentity::FsPath { path }
                | effinterp_proto::ResourceIdentity::BlockDevice { device: path } => {
                    identity.kind = ResourceKind::HostPath;
                    identity.name = Known(path.clone());
                    identity.details = Known(ResourceDetails::Path {
                        lexical: nah_proto::ctx::AbsolutePath::new(platform, path)
                            .ok()
                            .map_or(Unknown, Known),
                    });
                }
                effinterp_proto::ResourceIdentity::Process {
                    executable,
                    argv,
                    cwd,
                    ..
                } => {
                    identity.kind = ResourceKind::Process;
                    identity.name = Known(executable.clone());
                    let argv = argv
                        .iter()
                        .map(|v| match text(v) {
                            Known(v) => Some(v),
                            Unknown => None,
                        })
                        .collect::<Option<Vec<_>>>();
                    identity.details = Known(ResourceDetails::Process {
                        executable: Known(executable.clone()),
                        argv: argv.map_or(Unknown, Known),
                        cwd: cwd.as_deref().map_or(Unknown, path),
                    });
                }
                effinterp_proto::ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme,
                    port,
                    path,
                } => {
                    identity.kind = ResourceKind::Endpoint;
                    identity.name = Known(host.clone());
                    identity.provider = scheme.clone().map_or(Unknown, Known);
                    identity.details = Known(ResourceDetails::Endpoint {
                        host: Known(host.clone()),
                        scheme: scheme.clone().map_or(Unknown, Known),
                        port: port.map_or(Unknown, Known),
                        path: path.clone().map_or(Unknown, Known),
                    });
                }
                effinterp_proto::ResourceIdentity::GitRepository {
                    worktree, git_dir, ..
                } => {
                    identity.kind = ResourceKind::GitRepository;
                    identity.details = Known(ResourceDetails::Git {
                        worktree: worktree.as_deref().map_or(Unknown, path),
                        git_dir: git_dir.as_deref().map_or(Unknown, path),
                        reference: Unknown,
                    });
                }
                effinterp_proto::ResourceIdentity::CredentialStore {
                    provider,
                    store,
                    path,
                } => {
                    identity.kind = ResourceKind::CredentialStore;
                    identity.provider = Known(provider.clone());
                    identity.details = Known(ResourceDetails::Credential {
                        store: store.clone().map_or(Unknown, Known),
                        object: path.clone().map_or(Unknown, Known),
                    });
                }
                // An object store's identity is its bucket and, when the
                // invocation selects inside it, the key or key prefix. The
                // engine leaves unnamed scope dimensions Unknown; a missing
                // account or region is not grounds to drop the bucket. Nah's
                // kind vocabulary has no word for an object tree, so this is
                // the same `Other` the shipped producer publishes for it.
                effinterp_proto::ResourceIdentity::ObjectStore {
                    provider,
                    bucket,
                    key,
                    ..
                } => {
                    identity.kind = ResourceKind::Other;
                    identity.provider = provider.clone().map_or(Unknown, Known);
                    identity.name = Known(bucket.clone());
                    identity.details = Known(ResourceDetails::ObjectStore {
                        bucket: Known(bucket.clone()),
                        key: key.clone().map_or(Unknown, Known),
                    });
                }
                // Only the managed cloud resources whose deletion is a storage
                // loss are named here; every other service and kind keeps the
                // translation gap rather than arriving as an identified
                // storage resource.
                effinterp_proto::ResourceIdentity::CloudResource {
                    provider,
                    service,
                    kind,
                    id,
                    ..
                } if cloud_storage_target(service, kind).is_some() => {
                    identity.kind = match cloud_storage_target(service, kind) {
                        Some(effects::StorageTarget::Snapshot) => ResourceKind::Snapshot,
                        Some(effects::StorageTarget::LiveVolume) => ResourceKind::LiveVolume,
                        _ => ResourceKind::Other,
                    };
                    // The effect model names a cloud by the client that
                    // reaches it, so the vendor identity the engine carries is
                    // stated in that vocabulary here.
                    identity.provider = match provider.as_deref() {
                        Some("gcp") => Known("gcloud".into()),
                        Some("azure") => Known("az".into()),
                        Some(other) => Known(other.into()),
                        None => Unknown,
                    };
                    identity.name = id.clone().map_or(Unknown, Known);
                    identity.details = Known(ResourceDetails::Storage {
                        location: id.clone().map_or(Unknown, Known),
                    });
                }
                effinterp_proto::ResourceIdentity::StorageVolume { manager, name } => {
                    identity.kind = ResourceKind::LiveVolume;
                    identity.provider = Known(manager.clone());
                    identity.name = Known(name.clone());
                    identity.details = Known(ResourceDetails::Storage {
                        location: Known(name.clone()),
                    });
                }
                effinterp_proto::ResourceIdentity::ServiceUnit { manager, name } => {
                    identity.kind = ResourceKind::Service;
                    identity.provider = Known(manager.clone());
                    identity.name = Known(name.clone());
                    identity.details = Known(ResourceDetails::System {
                        unit: Known(name.clone()),
                        owner: Unknown,
                    });
                }
                effinterp_proto::ResourceIdentity::ScheduledJob { scheduler, owner } => {
                    identity.kind = ResourceKind::Job;
                    identity.provider = Known(scheduler.clone());
                    identity.details = Known(ResourceDetails::System {
                        unit: Unknown,
                        owner: owner.clone().map_or(Unknown, Known),
                    });
                }
                effinterp_proto::ResourceIdentity::EnvironmentVariable { name } => {
                    identity.name = Known(name.clone());
                }
                effinterp_proto::ResourceIdentity::HostSystem {} => {
                    identity.kind = ResourceKind::HostSystem
                }
                effinterp_proto::ResourceIdentity::Container { runtime, name, .. } => {
                    identity.kind = ResourceKind::ContainerResource;
                    identity.provider = Known(runtime.clone());
                    identity.name = name.clone().map_or(Unknown, Known);
                    identity.details = Known(ResourceDetails::Container {
                        runtime: Known(runtime.clone()),
                        namespace: Unknown,
                        volume: Unknown,
                    });
                }
                effinterp_proto::ResourceIdentity::ManagedInfrastructure {
                    tool, address, ..
                } => {
                    identity.kind = ResourceKind::ManagedInfrastructure;
                    identity.provider = Known(tool.clone());
                    identity.name = address.clone().map_or(Unknown, Known);
                    identity.details = Known(ResourceDetails::Infrastructure {
                        namespace: Unknown,
                        cluster: Unknown,
                        address: address.clone().map_or(Unknown, Known),
                    });
                }
                effinterp_proto::ResourceIdentity::KubernetesResource {
                    api_group,
                    kind,
                    name,
                    namespace,
                    ..
                } => {
                    identity.kind = ResourceKind::ManagedInfrastructure;
                    identity.provider = Known("kubernetes".into());
                    // A bulk or selector deletion resolves no name; the kind it
                    // acts on is still established.
                    identity.name = text(name);
                    // An unknown namespace scope is the engine saying it could
                    // not place the target in the cluster at all — an unmodeled
                    // kind, or several kinds named at once. That is the target's
                    // own identity, so it stays a translation gap even though
                    // the API endpoint beside it is the environment's.
                    incomplete_identity = matches!(
                        namespace,
                        effinterp_proto::KubernetesNamespace::Unknown { .. }
                    );
                    identity.details = Known(ResourceDetails::Infrastructure {
                        namespace: match namespace {
                            effinterp_proto::KubernetesNamespace::Namespaced { namespace }
                            | effinterp_proto::KubernetesNamespace::Unknown { namespace } => {
                                text(namespace)
                            }
                            effinterp_proto::KubernetesNamespace::Cluster => Unknown,
                        },
                        // The engine's server and context are an endpoint and a
                        // configuration label; neither identifies a cluster.
                        cluster: Unknown,
                        address: Known(if api_group.is_empty() {
                            kind.clone()
                        } else {
                            format!("{api_group}/{kind}")
                        }),
                    });
                }
                effinterp_proto::ResourceIdentity::Artifact {
                    ecosystem,
                    endpoint,
                    name,
                    reference,
                } => {
                    identity.kind = match ecosystem {
                        effinterp_proto::ArtifactEcosystem::Npm => ResourceKind::Package,
                        effinterp_proto::ArtifactEcosystem::Oci => ResourceKind::ContainerResource,
                        effinterp_proto::ArtifactEcosystem::GithubRelease => {
                            ResourceKind::HostedResource
                        }
                    };
                    identity.provider = Known(
                        match ecosystem {
                            effinterp_proto::ArtifactEcosystem::Npm => "npm",
                            effinterp_proto::ArtifactEcosystem::Oci => "oci",
                            effinterp_proto::ArtifactEcosystem::GithubRelease => "github",
                        }
                        .into(),
                    );
                    identity.name = text(name);
                    identity.details = Known(
                        if *ecosystem == effinterp_proto::ArtifactEcosystem::GithubRelease {
                            ResourceDetails::Hosted {
                                repository: text(name),
                                object_kind: Known("release".into()),
                                object: reference.value().map_or(Unknown, text),
                            }
                        } else {
                            ResourceDetails::Package {
                                registry: text(endpoint),
                                version: reference.value().map_or(Unknown, text),
                            }
                        },
                    );
                    if matches!(
                        reference.as_ref(),
                        effinterp_proto::ArtifactReference::Whole {}
                    ) {
                        selection = Selection::Whole;
                    }
                }
                _ => {}
            }
        }
        effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
        } => {
            identity.kind = ResourceKind::HostPath;
            selection = Selection::Pattern {
                pattern: glob.clone(),
                bound: effects::Bound::Unknown,
            };
        }
        // A unit selector reaches whichever units match it. The manager is the
        // established identity and the glob is the selection; no single unit
        // name is missing, because the invocation named none.
        effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::ServiceUnit { manager, name_glob },
        } => {
            identity.kind = ResourceKind::Service;
            identity.provider = match manager {
                effinterp_proto::Field::Exact { value } => Known(value.clone()),
                effinterp_proto::Field::Any => Unknown,
            };
            selection = Selection::Pattern {
                pattern: name_glob.clone(),
                bound: effects::Bound::Unknown,
            };
        }
        // Runtime cleanup names the runtime it sweeps and no container in it.
        // The runtime is the established identity; an absent name glob is the
        // absence of a named container, not an unidentified resource.
        effinterp_proto::ResourceExpr::Pattern {
            pattern:
                effinterp_proto::ResourcePattern::Container {
                    runtime,
                    name_glob,
                    image_glob,
                },
        } => {
            let runtime = match runtime {
                effinterp_proto::Field::Exact { value } => Known(value.clone()),
                effinterp_proto::Field::Any => Unknown,
            };
            identity.kind = ResourceKind::ContainerResource;
            identity.provider = runtime.clone();
            identity.details = Known(ResourceDetails::Container {
                runtime,
                namespace: Unknown,
                volume: Unknown,
            });
            if let Some(glob) = name_glob.as_ref().or(image_glob.as_ref()) {
                selection = Selection::Pattern {
                    pattern: glob.clone(),
                    bound: effects::Bound::Unknown,
                };
            }
        }
        resource if crate::observation_request::finite_members(resource).is_some() => {
            let members = crate::observation_request::finite_members(resource).unwrap();
            identity.kind = ResourceKind::HostPath;
            selection = Selection::NamedSet {
                identities: members
                    .iter()
                    .map(|member| effects::ResourceIdentity {
                        kind: ResourceKind::HostPath,
                        provider: Unknown,
                        name: text(member),
                        details: Known(ResourceDetails::Path {
                            lexical: path(member),
                        }),
                    })
                    .collect(),
                bound: effects::Bound::Finite(members.len() as u64),
            };
        }
        resource if crate::observation_request::subtree_root(resource).is_some() => {
            let root = crate::observation_request::subtree_root(resource).unwrap();
            let root = nah_proto::ctx::AbsolutePath::new(platform, root)
                .ok()
                .map_or(Unknown, Known);
            identity.kind = ResourceKind::HostPath;
            identity.details = Known(ResourceDetails::Path {
                lexical: root.clone(),
            });
            selection = Selection::Subtree { root };
        }
        _ => {}
    }
    if effect_target
        // An environment variable's whole identity is its name, and Nah's
        // resource vocabulary has no kind to carry it. A named variable or
        // the explicitly selected whole environment needs no other identity.
        && !matches!(
            resource,
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { .. }
            }
        )
        && !matches!(resource, effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::EnvironmentVariable { name_glob },
        } if name_glob == "*")
        // The machine the invocation runs on is named by being that machine.
        // A power action and a clock change reach the whole host, so there is
        // no further component to carry and none is missing.
        && !matches!(
            resource,
            effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::HostSystem {}
            }
        )
        && (incomplete_identity || components_unavailable(&identity, &selection))
    {
        add_gap(
            graph,
            effects::CallId(0),
            None,
            effects::GapPhase::Translation,
            "resource-components-unavailable",
        );
    }
    let id = effects::ResourceId(graph.resources.len() as u32);
    graph.resources.push(effects::EffectResource {
        id,
        realm: convert_realm(realm),
        identity,
        selection,
        labels: None,
    });
    id
}

/// Add a labeled host path resource that a Git discard's selection names.
pub(super) fn add_structural_path_resource(
    graph: &mut effects::EffectGraph,
    path: nah_proto::ctx::AbsolutePath,
    operation: effects::FilesystemOperation,
    authority: &crate::plan_view::AuthorityContext,
) -> effects::ResourceId {
    use effects::{
        EffectResource, FilesystemOperation, Reach, Realm, ResourceDetails, ResourceId,
        ResourceIdentity, ResourceKind, ResourceLabels, Selection,
    };
    // The engine spells a Windows selection with `/`; the observed roots its
    // labels are compared with use the host's `\`.
    let path = if authority.platform() == nah_proto::ctx::Platform::Windows {
        nah_proto::ctx::AbsolutePath::new(authority.platform(), path.as_str().replace('/', "\\"))
            .expect("respelled absolute path")
    } else {
        path
    };
    let label_operation = if operation == FilesystemOperation::Delete {
        nah_proto::action::FilesystemOperation::Delete
    } else {
        nah_proto::action::FilesystemOperation::Write
    };
    let scope = nah_proto::labels::scope::path_scope(
        &path,
        authority.observed_roots(),
        authority.home(),
        authority.platform(),
    );
    let protection = nah_proto::labels::tier::nah_protection_tier(
        label_operation,
        &path,
        &path,
        authority.observed_roots(),
        authority.trusted_roots(),
        authority.home(),
        authority.critical_paths(),
        authority.platform(),
        false,
        operation == FilesystemOperation::Delete,
    );
    let host_integrity = nah_proto::labels::host_integrity::host_integrity_class(
        label_operation,
        path.as_str(),
        &path,
        authority.home(),
        authority.platform(),
        false,
        false,
    );
    let sensitivity = nah_proto::labels::sensitivity::sensitivity(
        path.as_str(),
        &path,
        authority.home(),
        authority.platform(),
        false,
    );
    let selects_project =
        matches!(&scope, nah_proto::labels::PathScope::Project { root } if root == &path);
    let selects_home = nah_proto::labels::selects_home(
        path.as_str(),
        authority.home().as_str(),
        authority.platform(),
        false,
    );
    let id = ResourceId(graph.resources.len() as u32);
    graph.resources.push(EffectResource {
        id,
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind: ResourceKind::HostPath,
            provider: Unknown,
            name: Unknown,
            details: Known(ResourceDetails::Path {
                lexical: Known(path.clone()),
            }),
        },
        selection: Selection::Exact,
        labels: Some(ResourceLabels {
            lexical: Known(path.clone()),
            canonical: Unknown,
            scope: Known(scope),
            sensitivity: Known(sensitivity),
            protection: Known(protection),
            host_integrity: Known(host_integrity.into_iter().collect()),
            selects_project: if selects_project {
                Reach::Yes
            } else {
                Reach::No
            },
            selects_home: if selects_home { Reach::Yes } else { Reach::No },
            selects_root: if path.as_str() == "/" {
                Reach::Yes
            } else {
                Reach::No
            },
            is_symlink: Unknown,
            link_target: Unknown,
            descendants_complete: Unknown,
            reach: vec![],
        }),
    });
    id
}

/// Publish a feasible source-to-execution summary for a conditional staged file.
pub(super) fn convert_condition(
    condition: Option<&effinterp_proto::Condition>,
    graph: &mut effects::EffectGraph,
    atoms: &mut BTreeMap<String, u32>,
) -> Option<effects::ConditionUse> {
    use effects::{
        AlternativeGroupId, CallId, ConditionAtomOrigin, ConditionExpr, ConditionId, ConditionUse,
        Domain, EffectCondition, GapPhase,
    };
    let condition = condition?;
    let mut alternative_group = None;
    let expression = match condition {
        effinterp_proto::Condition::Atom { atom } => {
            let key = if atom.polarity.is_some() {
                format!("boolean:{}", effinterp_proto::canonical_json(&atom.origin))
            } else {
                effinterp_proto::canonical_json(&(&atom.origin, atom.arm))
            };
            let next = atoms.len() as u32;
            let id = *atoms.entry(key).or_insert(next);
            let origin = format!("group:{}", effinterp_proto::canonical_json(&atom.origin));
            let next = atoms.len() as u32;
            let group = *atoms.entry(origin).or_insert(next);
            if atom.arms > 1 {
                alternative_group = Some(AlternativeGroupId(group));
            }
            // Both outcomes of a two-way atom share one literal asserting its
            // first arm; the other outcome is that literal negated.
            let literal = ConditionExpr::Literal {
                atom: id,
                origin: Some(ConditionAtomOrigin {
                    kind: atom.origin.kind,
                    polarity: atom.polarity.map(|_| true),
                }),
            };
            if atom.polarity == Some(false) {
                let inner = graph
                    .conditions
                    .iter()
                    .find(|node| node.expression == literal)
                    .map(|node| node.id)
                    .unwrap_or_else(|| {
                        let inner = ConditionId(graph.conditions.len() as u32);
                        graph.conditions.push(EffectCondition {
                            id: inner,
                            expression: literal,
                            alternative_group: None,
                            complete: true,
                        });
                        inner
                    });
                ConditionExpr::Not(inner)
            } else {
                literal
            }
        }
        effinterp_proto::Condition::All { conditions }
        | effinterp_proto::Condition::Any { conditions } => {
            let ids = conditions
                .iter()
                .filter_map(|c| convert_condition(Some(c), graph, atoms).map(|c| c.id))
                .collect();
            if matches!(condition, effinterp_proto::Condition::All { .. }) {
                ConditionExpr::All(ids)
            } else {
                ConditionExpr::Any(ids)
            }
        }
        effinterp_proto::Condition::Widened => {
            add_gap(
                graph,
                CallId(0),
                Some(Domain::Causal),
                GapPhase::Translation,
                "condition-widened",
            );
            let atom = atoms.len() as u32;
            atoms.insert(format!("widened-{atom}"), atom);
            ConditionExpr::Literal { atom, origin: None }
        }
    };
    if let Some(node) = graph
        .conditions
        .iter()
        .find(|node| node.expression == expression && node.alternative_group == alternative_group)
    {
        return Some(ConditionUse {
            id: node.id,
            positive: true,
        });
    }
    let id = ConditionId(graph.conditions.len() as u32);
    graph.conditions.push(EffectCondition {
        complete: !matches!(condition, effinterp_proto::Condition::Widened),
        id,
        expression,
        alternative_group,
    });
    Some(ConditionUse { id, positive: true })
}

fn selection_reach(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
) -> Vec<effects::IdentityReach> {
    let mut identities = BTreeSet::new();
    let recursive_concrete = recursive_concrete_selection_root(effect);
    identities.insert(view.authority().home().clone());
    identities.extend(
        view.authority()
            .observed_roots()
            .iter()
            .map(|root| root.path().clone()),
    );
    if let Some(value) = crate::observation_request::observation_bound(&effect.resource)
        .and_then(|(path, _)| view.observed_path(&path))
    {
        identities.insert(value.resolved().clone());
        identities.extend(value.realpath().cloned());
        if recursive_concrete.is_none()
            && let Some(descendants) = value.descendants()
        {
            identities.extend(descendants.paths().iter().cloned());
        }
    }
    let mut bindings = effinterp_proto::Bindings::from_subject(&view.plan().subject);
    bindings.platform = if view.authority().platform() == nah_proto::ctx::Platform::Windows {
        effinterp_proto::PathPlatform::Windows
    } else {
        effinterp_proto::PathPlatform::Posix
    };
    let extglob = match &effect.resource {
        effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
        } if nah_proto::labels::pattern::holds_extglob(glob) => Some(glob),
        _ => None,
    };
    identities
        .into_iter()
        .map(|identity| {
            let concrete = effinterp_proto::QualifiedIdentity {
                realm: effinterp_proto::ExecutionRealm::Host,
                identity: effinterp_proto::ResourceIdentity::FsPath {
                    path: identity.as_str().into(),
                },
            };
            let reach =
                if unconditionally_selects_path(effect, &identity, view.authority().platform()) {
                    effects::Reach::Yes
                } else if let Some(glob) = extglob {
                    // The plan contract's matcher reads an extglob group as
                    // literal text, so it would answer that nothing is
                    // selected.
                    match nah_proto::labels::pattern::extglob_selects(
                        glob,
                        identity.as_str(),
                        view.authority().platform(),
                    ) {
                        Some(true) => effects::Reach::Yes,
                        Some(false) => effects::Reach::No,
                        None => effects::Reach::Unknown,
                    }
                } else {
                    match effinterp_proto::satisfies(
                        &concrete,
                        &effect.qualified_resource(),
                        &bindings,
                    ) {
                        effinterp_proto::Match::Satisfied { .. } => effects::Reach::Yes,
                        effinterp_proto::Match::NotSatisfied => effects::Reach::No,
                        effinterp_proto::Match::Indeterminate { .. } => effects::Reach::Unknown,
                    }
                };
            effects::IdentityReach { identity, reach }
        })
        .collect()
}

/// Whether an FsPath glob is its literal bound followed by `**/*`, which
/// selects every entry that is not hidden at every depth below the bound.
fn selects_every_depth(resource: &effinterp_proto::ResourceExpr) -> bool {
    if !matches!(
        resource,
        effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { .. }
        }
    ) {
        return false;
    }
    crate::observation_request::observation_bound(resource)
        .is_some_and(|(_, tail)| tail.strip_prefix('/').unwrap_or(tail) == "**/*")
}

fn recursive_concrete_selection_root(effect: &effinterp_proto::Effect) -> Option<&str> {
    let recursive = effect.attributes.get("recursive")
        == Some(&effinterp_proto::AttrValue::Bool(true))
        || effect.operation.as_str() == "filesystem.move";
    if !recursive {
        return None;
    }
    match &effect.resource {
        effinterp_proto::ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

/// Whether a recursive effect on a concrete path selects `path` whatever the observation says.
pub(super) fn unconditionally_selects_path(
    effect: &effinterp_proto::Effect,
    path: &nah_proto::ctx::AbsolutePath,
    platform: nah_proto::ctx::Platform,
) -> bool {
    recursive_concrete_selection_root(effect)
        .is_some_and(|root| nah_proto::labels::lexically_contains(root, path.as_str(), platform))
}

/// Whether a resource is the whole-environment pattern `*`.
pub(super) fn whole_environment(resource: &effinterp_proto::ResourceExpr) -> bool {
    matches!(
        resource,
        effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::EnvironmentVariable { name_glob },
        } if name_glob == "*"
    )
}

/// Collect the environment variable names a resource expression reads.
pub(super) fn resource_environment_names(
    resource: &effinterp_proto::ResourceExpr,
    names: &mut BTreeSet<String>,
) {
    match resource {
        effinterp_proto::ResourceExpr::Environment { name } => {
            names.insert(name.clone());
        }
        effinterp_proto::ResourceExpr::Property { base, .. } => {
            resource_environment_names(base, names)
        }
        effinterp_proto::ResourceExpr::Join { parts }
        | effinterp_proto::ResourceExpr::Union {
            alternatives: parts,
        } => {
            for part in parts {
                resource_environment_names(part, names);
            }
        }
        effinterp_proto::ResourceExpr::Concrete { identity } => match identity {
            effinterp_proto::ResourceIdentity::Process { argv, cwd, .. } => {
                for value in argv {
                    resource_environment_names(value, names);
                }
                if let Some(cwd) = cwd {
                    resource_environment_names(cwd, names);
                }
            }
            effinterp_proto::ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => {
                for value in [worktree, git_dir, pathspec].into_iter().flatten() {
                    resource_environment_names(value, names);
                }
            }
            effinterp_proto::ResourceIdentity::Artifact {
                endpoint,
                name,
                reference,
                ..
            } => {
                resource_environment_names(endpoint, names);
                resource_environment_names(name, names);
                if let Some(value) = reference.value() {
                    resource_environment_names(value, names);
                }
            }
            _ => {
                for value in identity.infrastructure_values() {
                    resource_environment_names(value, names);
                }
            }
        },
        effinterp_proto::ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::Process { argv_prefix, .. },
        } => {
            for value in argv_prefix {
                resource_environment_names(value, names);
            }
        }
        _ => {}
    }
}
