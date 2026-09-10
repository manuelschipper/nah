//! Binds interpreted Git facts to their shared call and resource identities.

use Knowledge::Unknown;
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
    payloads: Vec<FactPayload>,
    show: bool,
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
