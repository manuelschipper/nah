//! Binds interpreted infrastructure, storage, package and system facts to stage calls.

use Knowledge::{Known, Unknown};
use nah_proto::effects::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationEvidence {
    pub resource: EffectResource,
    pub payload: FactPayload,
    pub expand_tilde: bool,
}

impl OperationEvidence {
    pub(crate) fn new(kind: ResourceKind, realm: Realm, payload: FactPayload) -> Self {
        Self {
            resource: EffectResource {
                id: ResourceId(0),
                realm,
                identity: ResourceIdentity {
                    kind,
                    details: Unknown,
                    provider: Unknown,
                    name: Unknown,
                },
                selection: Selection::Unknown,
                labels: None,
            },
            payload,
            expand_tilde: false,
        }
    }

    pub(crate) fn provider(mut self, provider: &str) -> Self {
        self.resource.identity.provider = Known(provider.into());
        self
    }

    pub(crate) fn name(mut self, name: Option<&str>) -> Self {
        self.resource.identity.name = name.map_or(Unknown, |name| Known(name.into()));
        self
    }

    pub(crate) fn emit(
        mut self,
        graph: &mut EffectGraph,
        call: CallId,
        cwd: Option<&nah_proto::ctx::AbsolutePath>,
        home: &nah_proto::ctx::AbsolutePath,
        platform: nah_proto::ctx::Platform,
    ) {
        if let FactPayload::StorageChange {
            kind,
            recursive,
            operation,
            selection,
            ..
        } = &mut self.payload
        {
            if self.resource.realm == Realm::Host
                && matches!(kind, StorageTarget::Subvolume | StorageTarget::ObjectTree)
            {
                self.resource.identity.kind = ResourceKind::HostPath;
                if let Known(name) = &self.resource.identity.name {
                    let path = crate::paths::resolve_from_cwd(
                        cwd.map(nah_proto::ctx::AbsolutePath::as_str),
                        cwd.map(nah_proto::ctx::AbsolutePath::as_str),
                        name,
                        home.as_str(),
                        platform,
                        self.expand_tilde,
                    )
                    .and_then(|path| nah_proto::ctx::AbsolutePath::new(platform, path).ok());
                    self.resource.identity.details = Known(ResourceDetails::Path {
                        lexical: path.clone().map_or(Unknown, Known),
                    });
                    if *recursive == Known(true) || *operation == StorageOperation::Sync {
                        *selection = Selection::Subtree {
                            root: path.map_or(Unknown, Known),
                        };
                    }
                }
            } else {
                self.resource.identity.details = Known(ResourceDetails::Storage {
                    location: self.resource.identity.name.clone(),
                });
            }
            self.resource.selection = selection.clone();
        }
        let id = ResourceId(graph.resources.len() as u32);
        self.resource.id = id;
        match &mut self.payload {
            FactPayload::StorageChange { target, .. }
            | FactPayload::ContainerChange { target, .. }
            | FactPayload::InfrastructureChange { target, .. }
            | FactPayload::PackageChange { target, .. }
            | FactPayload::SystemChange { target, .. } => *target = id,
            _ => unreachable!(
                "operation evidence owns infrastructure, storage, package and system facts"
            ),
        }
        graph.facts.push(EffectFact {
            id: FactId(graph.facts.len() as u32),
            call,
            realm: self.resource.realm.clone(),
            // Recognition establishes an operation summary, not exact syscall execution.
            certainty: Certainty::Exact,
            modality: Modality::May,
            condition: None,
            occurrences: None,
            payload: self.payload,
        });
        graph.resources.push(self.resource);
    }
}

/// An interpreted system action may be proven while its host or unit remains unknown.
pub(crate) fn system_action(operation: SystemOperation, realm: Realm) -> OperationEvidence {
    OperationEvidence::new(
        if operation == SystemOperation::ServiceStop {
            ResourceKind::Service
        } else {
            ResourceKind::HostSystem
        },
        realm,
        FactPayload::SystemChange {
            target: ResourceId(0),
            operation,
            selection: Selection::Unknown,
            runtime_only: Unknown,
            persistent: Unknown,
            active: Known(true),
            cancel: Known(false),
            help: Known(false),
        },
    )
}

/// Whole running-container selection is a producer-established enumeration summary.
pub(crate) fn container_stop_all() -> OperationEvidence {
    OperationEvidence::new(
        ResourceKind::ContainerResource,
        Realm::Unknown,
        FactPayload::ContainerChange {
            target: ResourceId(0),
            operation: ContainerOperation::Stop,
            selection: Selection::Whole,
            broad_unused: Unknown,
            anonymous_volumes: Unknown,
            named_volumes: Unknown,
            attached_volume_removal: Known(false),
            all: Known(true),
            active: Known(true),
            dry_run: Known(false),
        },
    )
}
