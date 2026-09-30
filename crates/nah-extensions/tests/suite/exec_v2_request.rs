#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::fs;

use nah_extensions::consult_extensions;

use support::Fixture;

#[test]
fn guards_receive_the_exec_v2_evidence_request_without_private_types() {
    let fixture = Fixture::shell(
        "effinterp-shape",
        r#"cat > "$PWD/request.json"
printf '%s\n' '{"block":true,"reason":"shaped"}'"#,
    );
    let evidence = fixture.evidence.clone();

    consult_extensions(
        &fixture.catalog,
        &fixture.ctx,
        &fixture.observation,
        &evidence,
        &fixture.cache,
        &crate::support::memo_context(),
    );

    let request: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture.run.parent().unwrap().join("request.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(request["v"], 2);
    assert!(request["evidence"]["calls"].is_array());
    assert!(request.get("action_stream").is_none());
    assert!(request["observation"].is_object());
}

#[test]
fn memo_key_changes_with_private_evidence_despite_identical_exec_v2_requests() {
    let fixture = Fixture::shell(
        "effinterp-memo",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
printf '%s' "$((count + 1))" > "$count_file"
printf '%s\n' '{"block":true,"reason":"counted"}'"#,
    );
    let evidence = fixture.evidence.clone();
    use Knowledge::{Known, Unknown};
    use nah_proto::effects::*;
    let mut graph = evidence.graph().clone();
    let identity = ResourceIdentity {
        kind: ResourceKind::Process,
        name: Known("python3".into()),
        provider: Unknown,
        details: Known(ResourceDetails::Process {
            executable: Known("python3".into()),
            argv: Unknown,
            cwd: Unknown,
        }),
    };
    graph.resources.push(EffectResource {
        id: ResourceId(0),
        realm: Realm::Host,
        identity: identity.clone(),
        labels: None,
        selection: Selection::NamedSet {
            identities: vec![identity],
            bound: Bound::Finite(1),
        },
    });
    let mut public = evidence.public_selection().clone();
    public.resources.insert(ResourceId(0));
    let evidence = GuardEvidence::new(graph, public).unwrap();

    for (secret, environment) in [
        ("private-body-one", "one"),
        ("different-private-body-two", "one"),
        ("different-private-body-two", "two"),
    ] {
        use nah_proto::observation::*;
        let mut facts = fixture.observation.facts().to_vec();
        facts.push(
            ObservationFact::new(
                ObservationQuery::Env {
                    key: "private-env".into(),
                    name: "PRIVATE_VALUE".into(),
                },
                ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Value {
                            text: environment.into(),
                        },
                    },
                },
            )
            .unwrap(),
        );
        let observation = Observation::new(
            nah_proto::ctx::SchemaVersion::V1,
            fixture.observation.request_id(),
            facts,
        )
        .unwrap();
        let mut graph = evidence.graph().clone();
        if let Known(ResourceDetails::Process { argv, .. }) =
            &mut graph.resources[0].identity.details
        {
            *argv = Known(vec!["python3".into(), "-c".into(), secret.into()]);
        }
        let identity = graph.resources[0].identity.clone();
        if let Selection::NamedSet { identities, .. } = &mut graph.resources[0].selection {
            identities[0] = identity;
        }

        graph.calls[0].input = Some(
            nah_proto::tool::ToolCallInput::new(
                nah_proto::ctx::SchemaVersion::V1,
                "Bash",
                serde_json::json!({"command": secret}),
                "/repo",
                None,
            )
            .unwrap(),
        );
        // An unreferenced private condition is not part of the request either.
        graph.conditions.push(nah_proto::effects::EffectCondition {
            id: nah_proto::effects::ConditionId(0),
            expression: nah_proto::effects::ConditionExpr::Literal {
                atom: secret.len() as u32,
                origin: None,
            },
            alternative_group: None,
            complete: true,
        });
        let projected =
            nah_proto::effects::GuardEvidence::new(graph, evidence.public_selection().clone())
                .unwrap();
        let request = nah_extensions::exec_request(&projected, &observation).unwrap();
        assert_eq!(
            request,
            nah_extensions::exec_request(&evidence, &fixture.observation).unwrap()
        );
        assert!(!serde_json::to_string(&request).unwrap().contains(secret));
        assert!(!format!("{request:?}").contains(secret));
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &observation,
            &projected,
            &fixture.cache,
            &crate::support::memo_context(),
        );
    }

    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "3"
    );
}
