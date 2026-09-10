//! Binds interpreted Git facts and finalized filesystem identities to shared evidence.

use Knowledge::{Known, Unknown};
use nah_proto::action::EffectKind;
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::effects::*;

fn fact(graph: &mut EffectGraph, call: CallId, realm: Realm, payload: FactPayload) {
    graph.facts.push(EffectFact {
        id: FactId(graph.facts.len() as u32),
        call,
        realm,
        certainty: Certainty::Exact,
        modality: Modality::MustOnSuccess,
        condition: None,
        occurrences: None,
        payload,
    });
}

pub(crate) fn emit_git(
    graph: &mut EffectGraph,
    call: CallId,
    effects: &[EffectKind],
    payloads: Vec<FactPayload>,
    lexical_paths: &[(nah_proto::ctx::AbsolutePath, nah_proto::ctx::AbsolutePath)],
    show: bool,
    platform: Platform,
) {
    if payloads.is_empty()
        && !effects
            .iter()
            .any(|effect| matches!(effect, EffectKind::Filesystem { .. }))
    {
        return;
    }
    emit_stage_filesystems(graph, effects, lexical_paths, show, call, platform);
    for mut payload in payloads {
        let id = ResourceId(graph.resources.len() as u32);
        let (kind, realm) = match &mut payload {
            FactPayload::GitPush { repository, .. } => {
                *repository = id;
                (ResourceKind::GitRepository, Realm::Host)
            }
            FactPayload::GitDiscard { target, .. }
            | FactPayload::GitHistory { target, .. }
            | FactPayload::GitRecovery { target, .. }
            | FactPayload::GitRefChange { target, .. } => {
                *target = id;
                (ResourceKind::GitRepository, Realm::Host)
            }
            FactPayload::HostedDeletion { target, kind, .. } => {
                *target = id;
                (
                    if *kind == HostedTarget::Repository {
                        ResourceKind::HostedRepository
                    } else {
                        ResourceKind::HostedResource
                    },
                    Realm::Remote { identity: Unknown },
                )
            }
            _ => unreachable!("Git emitter accepts only interpreted Git and hosted deletion facts"),
        };
        graph.resources.push(EffectResource {
            id,
            realm: realm.clone(),
            identity: ResourceIdentity {
                kind,
                details: Unknown,
                name: Unknown,
                provider: Unknown,
            },
            selection: Selection::Unknown,
            labels: None,
        });
        fact(graph, call, realm, payload);
    }
}

pub(crate) fn emit_filesystems(
    graph: &mut EffectGraph,
    effects: &[EffectKind],
    observation: &nah_proto::observation::Observation,
    platform: Platform,
) {
    let lexical_paths = observation
        .facts()
        .iter()
        .filter_map(|fact| match fact.value() {
            nah_proto::observation::ObservationValue::Path {
                observed: nah_proto::observation::Observed::Ok { value },
            } => Some((
                value.realpath().unwrap_or_else(|| value.resolved()).clone(),
                value.resolved().clone(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !effects
        .iter()
        .any(|effect| matches!(effect, EffectKind::Filesystem { .. }))
    {
        return;
    }
    emit_stage_filesystems(graph, effects, &lexical_paths, false, CallId(0), platform);
}

fn emit_stage_filesystems(
    graph: &mut EffectGraph,
    effects: &[EffectKind],
    lexical_paths: &[(nah_proto::ctx::AbsolutePath, nah_proto::ctx::AbsolutePath)],
    show: bool,
    call: CallId,
    platform: Platform,
) {
    if show {
        fact(
            graph,
            call,
            Realm::Host,
            FactPayload::Other {
                operation: "git.show".into(),
                domain: "git".into(),
                resource_kind: "modeled".into(),
                resources: vec![],
            },
        );
    }
    for effect in effects {
        let EffectKind::Filesystem { effect } = effect else {
            continue;
        };
        let id = ResourceId(graph.resources.len() as u32);
        let lexical = lexical_paths
            .iter()
            .find(|(target, _)| target == &effect.target)
            .map_or(&effect.target, |(_, lexical)| lexical);
        let mut normalized =
            crate::self_protection_tiers::lexically_normalized(lexical.as_str(), platform);
        if platform == Platform::Windows && normalized.ends_with(':') {
            normalized.push('\\');
        }
        let lexical = AbsolutePath::new(platform, normalized)
            .expect("normalized absolute filesystem identity");
        let mut normalized_target =
            crate::self_protection_tiers::lexically_normalized(effect.target.as_str(), platform);
        if platform == Platform::Windows && normalized_target.ends_with(':') {
            normalized_target.push('\\');
        }
        let target = AbsolutePath::new(platform, normalized_target)
            .expect("normalized absolute filesystem target");
        let canonical = if lexical != target {
            Known(target.clone())
        } else {
            Unknown
        };
        graph.resources.push(EffectResource {
            id,
            realm: Realm::Host,
            identity: ResourceIdentity {
                kind: ResourceKind::HostPath,
                details: Known(ResourceDetails::Path {
                    lexical: Known(target.clone()),
                }),
                name: Unknown,
                provider: Unknown,
            },
            selection: if effect.pattern {
                Selection::Pattern {
                    pattern: target.as_str().into(),
                    bound: Bound::Unknown,
                }
            } else {
                Selection::Exact
            },
            labels: Some(ResourceLabels {
                lexical: Known(lexical),
                canonical,
                scope: Known(effect.scope.clone()),
                sensitivity: Known(effect.sensitivity),
                protection: Known(effect.protection),
                host_integrity: Known(effect.host_integrity.into_iter().collect()),
                selects_project: if effect.selects_root {
                    Reach::Yes
                } else {
                    Reach::No
                },
                selects_home: if effect.selects_home {
                    Reach::Yes
                } else {
                    Reach::No
                },
                selects_root: Reach::Unknown,
                is_symlink: Unknown,
                link_target: Unknown,
                descendants_complete: Unknown,
                reach: vec![],
            }),
        });
        let operation = match effect.operation {
            nah_proto::action::FilesystemOperation::Read => FilesystemOperation::Read,
            nah_proto::action::FilesystemOperation::Write => FilesystemOperation::Write,
            nah_proto::action::FilesystemOperation::Delete => FilesystemOperation::Delete,
        };
        fact(
            graph,
            call,
            Realm::Host,
            FactPayload::FilesystemAccess {
                operation,
                target: id,
                destination: None,
                recursive: Known(effect.recursive),
                truncate: Unknown,
                permissions: PermissionGrants {
                    world_write: Unknown,
                    setuid: Unknown,
                    setgid: Unknown,
                },
                purpose: AccessPurpose::Explicit,
            },
        );
    }
}
