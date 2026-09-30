//! The rendered text projection that `rendered` predicates test.
//!
//! This is a presentation of a resource, not its identity: two different
//! resources can render alike, and a textual prefix is not path containment.
//! Changing any rendering here changes what every stored `rendered` predicate
//! means, so it is part of the matcher's versioned contract.

use effinterp_proto::{ExecutionRealm, ResourceExpr, ResourceIdentity};

use crate::{ResourceField, ResourceVariant};

pub(crate) fn resource_variant(value: &ResourceVariant) -> &'static str {
    match value {
        ResourceVariant::Artifact => "artifact",
        ResourceVariant::ServiceUnit => "service_unit",
        ResourceVariant::StorageVolume => "storage_volume",
        ResourceVariant::CredentialStore { .. } => "credential_store",
        ResourceVariant::HostSystem => "host_system",
        ResourceVariant::FsPath => "filesystem_path",
        ResourceVariant::EnvironmentVariable { .. } => "environment_variable",
        ResourceVariant::Container => "container",
        ResourceVariant::KubernetesResource => "kubernetes_resource",
        ResourceVariant::ManagedInfrastructure => "managed_infrastructure",
        ResourceVariant::ObjectStore => "object_store",
        ResourceVariant::CloudResource => "cloud_resource",
    }
}

pub(crate) fn resource_field(value: ResourceField) -> &'static str {
    match value {
        ResourceField::StorageManager => "storage-volume manager",
        ResourceField::StorageName => "storage-volume name",
        ResourceField::KubernetesNamespace => "Kubernetes namespace",
        ResourceField::KubernetesSelection => "Kubernetes selection",
        ResourceField::ManagedWholeStack => "managed-infrastructure whole-stack flag",
        ResourceField::CloudProvider => "cloud provider",
        ResourceField::CloudService => "cloud service",
        ResourceField::CloudKind => "cloud kind",
    }
}

/// The resource rendering prefixed with `realm!` for a non-host realm.
pub fn rendered_resource_in_realm(realm: &ExecutionRealm, expr: &ResourceExpr) -> String {
    match realm {
        ExecutionRealm::Host => rendered_resource(expr),
        other => format!("{}!{}", self::realm(other), rendered_resource(expr)),
    }
}

fn realm(realm: &ExecutionRealm) -> String {
    use ExecutionRealm::*;
    match realm {
        Host => "host".to_string(),
        Container { runtime, name } => format!("{runtime}:{name}"),
        Kubernetes { pod, .. } => format!("pod:{pod}"),
        Chroot { host_root } => format!("chroot:{}", host_root.as_deref().unwrap_or("?")),
        Remote { endpoint } => format!("remote:{endpoint}"),
    }
}

/// The rendering of a resource expression, without its realm.
pub fn rendered_resource(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::FsPath { path } => path.clone(),
            ResourceIdentity::EnvironmentVariable { name } => format!("env:{name}"),
            identity @ ResourceIdentity::GitRepository { .. } => {
                effinterp_proto::display_identity(identity)
            }
            ResourceIdentity::Process { executable, .. } => executable.clone(),
            ResourceIdentity::NetworkEndpoint {
                host,
                scheme,
                port,
                path,
            } => {
                let scheme = scheme
                    .as_deref()
                    .map(|s| format!("{s}://"))
                    .unwrap_or_default();
                let port = port.map(|p| format!(":{p}")).unwrap_or_default();
                let path = path.as_deref().unwrap_or_default();
                format!("{scheme}{host}{port}{path}")
            }
            ResourceIdentity::Container { name, image, .. } => {
                match (name.as_deref(), image.as_deref()) {
                    (Some(name), Some(image)) => {
                        format!("container:{name} [image={image}]")
                    }
                    (Some(identity), None) | (None, Some(identity)) => {
                        format!("container:{identity}")
                    }
                    (None, None) => "container:?".to_string(),
                }
            }
            ResourceIdentity::DatabaseTable {
                server,
                database,
                schema,
                table,
            } => {
                let scope: Vec<&str> = [server.as_deref(), database.as_deref(), schema.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect();
                if scope.is_empty() {
                    format!("db:{table}")
                } else {
                    format!("db:{}.{table}", scope.join("."))
                }
            }
            ResourceIdentity::DatabaseSchema {
                server,
                database,
                schema,
            } => {
                let scope: Vec<&str> = [server.as_deref(), database.as_deref(), schema.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect();
                format!("db:{}", scope.join("."))
            }
            ResourceIdentity::ObjectStore { bucket, key, .. } => match key {
                Some(k) => format!("obj:{bucket}/{k}"),
                None => format!("obj:{bucket}"),
            },
            ResourceIdentity::CloudResource {
                service, kind, id, ..
            } => format!("cloud:{service}/{kind}/{}", id.as_deref().unwrap_or("?")),
            identity @ ResourceIdentity::Artifact { .. } => {
                effinterp_proto::display_identity(identity)
            }
            ResourceIdentity::MessageTopic { name, .. } => format!("topic:{name}"),
            ResourceIdentity::ServiceUnit { .. }
            | ResourceIdentity::ScheduledJob { .. }
            | ResourceIdentity::StorageVolume { .. }
            | ResourceIdentity::BlockDevice { .. }
            | ResourceIdentity::CredentialStore { .. }
            | ResourceIdentity::HostSystem { .. }
            | ResourceIdentity::UserHome { .. }
            | ResourceIdentity::KubernetesResource { .. }
            | ResourceIdentity::ManagedInfrastructure { .. } => {
                effinterp_proto::display_identity(identity)
            }
        },
        ResourceExpr::Literal { value } => value.clone(),
        ResourceExpr::Parameter { name } => format!("<{name}>"),
        ResourceExpr::Environment { name } => format!("${name}"),
        ResourceExpr::Property { base, name } => format!("{}.{name}", rendered_resource(base)),
        ResourceExpr::Join { parts } => {
            let parts: Vec<String> = parts.iter().map(rendered_resource).collect();
            format!("join({})", parts.join(", "))
        }
        ResourceExpr::Union { alternatives } => {
            let alternatives: Vec<String> = alternatives.iter().map(rendered_resource).collect();
            format!("one_of({})", alternatives.join(", "))
        }
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } => format!("filesystem:{glob}"),
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::EnvironmentVariable { name_glob },
        } => format!("environment:{name_glob}"),
        ResourceExpr::Pattern {
            pattern:
                effinterp_proto::ResourcePattern::NetworkEndpoint {
                    host_glob,
                    scheme: effinterp_proto::Field::Any,
                    port: effinterp_proto::PortField::Any,
                    path_prefix: None,
                },
        } => format!("network:{host_glob}"),
        ResourceExpr::Pattern {
            pattern:
                effinterp_proto::ResourcePattern::ServiceUnit {
                    manager: effinterp_proto::Field::Any,
                    name_glob,
                },
        } => format!("system:{name_glob}"),
        ResourceExpr::Pattern { pattern } => pattern.to_string(),
        ResourceExpr::Unresolved { family } => format!("<{}:?>", family.0),
    }
}
