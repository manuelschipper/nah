use effinterp_engine::Engine;
use effinterp_model_schema::FactAssertionFixture;
use effinterp_proto::{Plan, Subject, canonical_json, validate_plan};
use serde_json::Value;

const FIXTURES: &[(&str, &str)] = &[
    (
        "cat",
        include_str!("../fixtures/model_equivalence/cat.json"),
    ),
    (
        "chmod-chown",
        include_str!("../fixtures/model_equivalence/chmod_chown.json"),
    ),
    ("cp", include_str!("../fixtures/model_equivalence/cp.json")),
    ("ln", include_str!("../fixtures/model_equivalence/ln.json")),
    (
        "mkdir",
        include_str!("../fixtures/model_equivalence/mkdir.json"),
    ),
    ("mv", include_str!("../fixtures/model_equivalence/mv.json")),
    ("rm", include_str!("../fixtures/model_equivalence/rm.json")),
    (
        "rmdir",
        include_str!("../fixtures/model_equivalence/rmdir.json"),
    ),
    (
        "touch",
        include_str!("../fixtures/model_equivalence/touch.json"),
    ),
    (
        "truncate",
        include_str!("../fixtures/model_equivalence/truncate.json"),
    ),
];

#[test]
fn reviewed_matrix_subjects_produce_valid_plans() {
    for (model, fixture) in FIXTURES {
        let fixture: FactAssertionFixture = serde_json::from_str(fixture).unwrap();
        fixture.validate().unwrap();
        for (case, expected) in fixture.cases.into_iter().enumerate() {
            let actual = Engine::new()
                .with_causality_detail(true)
                .analyze(&expected.subject)
                .unwrap();
            validate_plan(&actual).unwrap_or_else(|errors| {
                panic!("{model} case {case} produced an invalid plan: {errors:?}")
            });
        }
    }
}

#[test]
fn equivalence_matrix_covers_every_required_axis() {
    let plans = FIXTURES
        .iter()
        .flat_map(|(_, fixture)| {
            serde_json::from_str::<FactAssertionFixture>(fixture)
                .unwrap()
                .cases
                .into_iter()
                .map(|case| {
                    Engine::new()
                        .with_causality_detail(true)
                        .analyze(&case.subject)
                        .unwrap()
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(plans.len(), 55);
    assert!(
        plans
            .iter()
            .any(|plan| matches!(plan.subject, effinterp_proto::Subject::Shell { .. }))
    );
    assert!(
        plans
            .iter()
            .any(|plan| { plan.effects.iter().any(|effect| !effect.realm.is_host()) })
    );
    assert!(plans.iter().any(|plan| !plan.boundaries.is_empty()));
    assert!(plans.iter().any(|plan| {
        matches!(
            &plan.subject,
            effinterp_proto::Subject::Exec { cwd: None, .. }
        )
    }));
    assert!(plans.iter().any(|plan| {
        plan.effects
            .iter()
            .any(|effect| !effect.attributes.is_empty())
    }));
}

#[test]
fn bun_install_single_owner_preserves_the_promoted_plan() {
    let fixtures: Vec<Value> =
        serde_json::from_str(include_str!("../fixtures/model_equivalence/bun.json")).unwrap();
    for mut expected in fixtures {
        let subject: Subject = serde_json::from_value(expected["subject"].clone()).unwrap();
        let actual = Engine::new()
            .with_causality_detail(true)
            .analyze(&subject)
            .unwrap();
        validate_plan(&actual).unwrap();
        expected["analysis"]["model_set"] = Value::String(actual.analysis.model_set.clone());
        for node in expected["provenance"].as_array_mut().unwrap() {
            if node["kind"] == "model_application" {
                node["model"] = Value::String("pkg/manager@v1".to_string());
            }
        }
        let expected: Plan = serde_json::from_value(expected).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn kubectl_reviewed_subjects_produce_valid_plans() {
    let fixture: FactAssertionFixture = serde_json::from_str(include_str!(
        "../fixtures/model_equivalence/kubectl_target.json"
    ))
    .unwrap();
    fixture.validate().unwrap();
    assert_eq!(fixture.cases.len(), 34);
    for (case, expected) in fixture.cases.into_iter().enumerate() {
        let actual = Engine::new()
            .with_causality_detail(true)
            .analyze(&expected.subject)
            .unwrap();
        validate_plan(&actual)
            .unwrap_or_else(|errors| panic!("kubectl case {case} is invalid: {errors:?}"));
    }
}

#[test]
fn cryptsetup_golden_pins_plan_protocol_serialization() {
    #[derive(serde::Serialize)]
    struct ProjectedAnalysis<'a> {
        engine_version: &'a str,
        limits: &'a effinterp_proto::Limits,
    }

    #[derive(serde::Serialize)]
    struct ProjectedPlan<'a> {
        schema: &'a str,
        subject: &'a Subject,
        analysis: ProjectedAnalysis<'a>,
        effects: &'a [effinterp_proto::Effect],
        execution_graph: &'a effinterp_proto::ExecutionGraph,
        #[serde(skip_serializing_if = "<[effinterp_proto::ProvenanceNode]>::is_empty")]
        provenance: &'a [effinterp_proto::ProvenanceNode],
        #[serde(skip_serializing_if = "<[effinterp_proto::Boundary]>::is_empty")]
        boundaries: &'a [effinterp_proto::Boundary],
        coverage: &'a effinterp_proto::Coverage,
        causality: &'a effinterp_proto::Causality,
    }

    let subject = Subject::Shell {
        source: "cryptsetup erase /dev/sda".to_string(),
        cwd: Some("/workspace/project".to_string()),
        context: effinterp_proto::HostContext {
            env: [("HOME".to_string(), "/home/test".to_string())].into(),
            ..Default::default()
        },
    };
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&subject)
        .unwrap();
    let projected = ProjectedPlan {
        schema: &plan.schema,
        subject: &plan.subject,
        analysis: ProjectedAnalysis {
            engine_version: &plan.analysis.engine_version,
            limits: &plan.analysis.limits,
        },
        effects: &plan.effects,
        execution_graph: &plan.execution_graph,
        provenance: &plan.provenance,
        boundaries: &plan.boundaries,
        coverage: &plan.coverage,
        causality: &plan.causality,
    };
    let mut actual = serde_json::to_string_pretty(&vec![projected]).unwrap();
    actual.push('\n');
    assert_eq!(
        actual.as_bytes(),
        include_bytes!("../fixtures/model_equivalence/cryptsetup.json"),
        "this byte comparison pins effinterp/plan/v1 serialization, not model semantics"
    );
}

// Plans from target 628908ab (before the scanner refactor) catch symbolic options
// being discarded or resolved and separators shifting operands (QA-251-1/2).
// Model provenance hashes are repinned when the bundled declaration document changes.
#[test]
fn argument_scanning_preserves_canonical_plans() {
    let cases = [
        (
            r#"sudo -u"$U" rm -rf /x"#,
            "530554e063e193add35677b919c3f23275c3c1fe1e7ac97c166fb7787ff234ae",
        ),
        (
            r#"sudo --userx rm /x"#,
            // Bare target selection also records the unread sudoers policy.
            "aa7e6a840ae76b8bf53e6a9437f91ef48d07153367892bdb7ed48dc491ef1910",
        ),
        (
            r#"nice --adjustmentx rm /x"#,
            "2f18d49d73652a04c5931e794e9715dade357f4c45aa9a375914d587a36c9970",
        ),
        (
            r#"rsync -- -a host:/b"#,
            "2e126816e1398eb13eb933e95defd8e10c682c704acb9ff1bf5021f4138d575b",
        ),
        (
            r#"git checkout -f x -- --"#,
            "017bd684d5653bce866eadb605e34500ed099c2732eb4b80e905c33e756643c2",
        ),
        (
            r#"git --"$F" rm x"#,
            "98561e54c1574c07d3075f67d2bbcdd391961ff127789cb037296259d9f34417",
        ),
        (
            r#"doas --"$F" rm -rf /x"#,
            "56a21a3add8c20acdfd34cb25ab911a16a29ce78413ff45bcb56aae96ad9ae7f",
        ),
        (
            r#"nice --"$F" rm /x"#,
            "a7120fb287fd319b3553aca9a88c14b87e2cf417b60b542b8689cbaf3a3e8eaa",
        ),
        (
            r#"nohup --"$F" rm /x"#,
            "6022e66705fbf0db7dad50151ebf32fdef1f7f8377bf422eb89f1de01a29bb23",
        ),
        (
            r#"setsid --"$F" rm /x"#,
            "b6304bd540d71762f08f2137031c232b5ca6669ba3922b105dd2319faf42596b",
        ),
        (
            r#"stdbuf --"$F" rm /x"#,
            "e4a67b4822cb159fd60b34d489f6013f89b6f51468d2254c6bf0f14e8c6de112",
        ),
        (
            r#"timeout --"$F" 3 rm /x"#,
            "8776d915c876524b4a267ff348256c96058f0ae80250fe5c8ee56c950f587d58",
        ),
        (
            r#"env --"$F" rm /x"#,
            "4be223a797262bcbabc3a0665010560b2df166fbcbe96fd132ce4418785e6a7c",
        ),
        (
            r#"sshpass --"$F" ssh host rm /x"#,
            "d5219c82dfce75db5f67af16807e5be4074f381cb0bfe89da3452c97592d52eb",
        ),
        (
            r#"runuser -c"$C" root rm /x"#,
            "99c58538b7f17f2aa2ea0ef285327b763f3aa8ec51f426021fd9e3305d6be1f3",
        ),
        (
            r#"runuser -u -c"$C" root rm /x"#,
            "83a88bf62ca8cfaba4539b86b7571f9d59a2df89600b2ad3382aa787aa50a3d4",
        ),
        (
            r#"runuser -fl root rm /x"#,
            "4f83d99e20db46b12cf5039e24d44216875b082686ac296371ee56772c2a73c1",
        ),
        (
            r#"su --user= root -c "rm /x""#,
            "617c4d2e8e095079c7107d7205649c10d2ab56f0ad8441993d5f2510c6b5e02b",
        ),
        (
            r#"docker exec - box rm /x"#,
            "6ce84f516943b14c65a14836cfa76e52972d18abc0fdcd15668a6de9f3bc6a5e",
        ),
        (
            r#"docker build - ."#,
            "9c6f80c997ab2d5beb07ec38ec058941c49fe170bdbe8c878e1554656d1d0c2f",
        ),
        (
            r#"docker run - alpine rm /x"#,
            "d1e78c55a66a45b67baf74dbf7b09c6f7f87f248771f429858271f65903efca5",
        ),
        (
            r#"docker --"$F" run alpine rm /x"#,
            "573d0ae3edc625f678d13e90c54be2a69de1a6d5a2129047c93578f8c0526c6d",
        ),
        (
            r#"git push --"$F" origin main"#,
            "89ffce7835b70762a4fdd6ff0fc4dde1ff400cfaacc3ef7a7c5959f3157c911e",
        ),
        (
            r#"wipefs --"$F" -a /dev/x"#,
            "62844216df3f00bb833034524c2315e77820ba70f931ec5ef7db5ef37a41b029",
        ),
        (
            r#"git rm x --"$F""#,
            "793dc5c66863522ae7c62fa35f18dced2f81e7ffcb165258f9070d0ee70f5f77",
        ),
        (
            r#"rsync a host:/b -- --"#,
            "b2853de22e1104dfafed369807e205d4e6e3b4c394bea2f53f9de6ebd4623895",
        ),
        (
            r#"scp a host:/b -- --"#,
            "c3ef2f7296c54e6b5dd87705d2e474ccff8839c54e31d82a59d5790040c614dd",
        ),
        (
            r#"rsync --"$F" a host:/b"#,
            "a82ba112fe508bc1f8d9becdcdb5c8419ee17fa9f147e74f56b3f7d45ca2411f",
        ),
        (
            r#"scp --"$F" a host:/b"#,
            "4dcab1cb3e8f5cac9321af94fc4b43657e72e4f442abd89bf8cb94d73e719932",
        ),
        (
            r#"aws -- -- s3 cp a s3://bucket/b"#,
            "72c33215e59100e73ed94dc09fcfa57feb7582bd4cfdc50c1bb370ec243d88bd",
        ),
        (
            r#"gcloud -- -- storage cp a gs://bucket/b"#,
            "91bc179bb0ed2dea9b8e4e1aa3a34a8e395ff3719272475767fa9b1e5cafda2a",
        ),
        (
            r#"nats -- -- pub topic msg"#,
            "7980fbb1d833ce76f7ef18cc634cd39f0c95f8133a7de6caf18cd81bd0b71c2b",
        ),
        (
            r#"rabbitmqadmin -- -- delete queue name=q"#,
            "323d99af6ca623d03dcd5fb964327bd9c00fae035b63c6a1ee31a0a02f4229ca",
        ),
        (
            r#"redis-cli -- -- DEL k"#,
            "fda753c67c57ced29fbdd9ceb716b660e83fdf21a4d052ed832e7aad6b86f007",
        ),
        (
            r#"git reset -- --hard"#,
            "d3ce45cea39f0376bf8fd3f7ffca9e8ca5ef6e1a0000a853b612c70135541484",
        ),
        (
            r#"git - rm x"#,
            "eff6c65ea2a1e66da51f7c13ba6305e1ad32d3916d779f7021e03636518ab3a1",
        ),
        (
            r#"psql -c --"$F" "DELETE FROM x""#,
            "623ab7651064b261bcd1f22868c67a3bc49c608fe0583d0cc252aa3d062d0276",
        ),
        (
            r#"psql --command="$C" -c "DELETE FROM x""#,
            "b5a5c248cf66c200fcc8f309b3d1942ca80a04400ef3cee0bd5d2ad81ea0c144",
        ),
        (
            r#"mysql -e --"$F" "DELETE FROM x""#,
            "d058e01d287a77bb009c75a789b645ae8abe662eedd3c17bdc0ca8d56c8533d9",
        ),
        (
            r#"wipefs -za /dev/x"#,
            "fbf5f42e1ae13e425ea42c4bdcf6f5dd63d1503d6d0e1f6bbad56a79874fe092",
        ),
        (
            r#"gzip -zk x"#,
            "94773037c38f74e92d3715d041c173f601d78baa89767206c16c7d4a885c156c",
        ),
        (
            r#"wipefs --all=x /dev/x"#,
            "ddb440b57d86b525b04b12c5d8fd1a169f97198d6814a60c874785d30a017e04",
        ),
        (
            r#"gzip --stdout=x x"#,
            "e9a085d0fff531646c107827a24093593cf2615040ae6b7fb8e2ab80e1e6c9ca",
        ),
        (
            r#"git push -of origin main"#,
            "f399a51abd360052ae25bfffea2757cd6ef81a70516ef8e83c922ec868747c13",
        ),
        (
            r#"rsync a host:/b -- --rsync-path="rm /x""#,
            "65ea4a9652737f7cae6cd66ff806472bd96f1e733a880f25613063bae7fbd822",
        ),
    ];
    let engine = Engine::new();
    for (source, expected) in cases {
        let subject = Subject::Shell {
            source: source.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        };
        let mut plan = engine.analyze(&subject).unwrap();
        validate_plan(&plan).unwrap();
        plan.analysis.model_set = "argument-parser-baseline".into();
        assert_eq!(
            blake3::hash(canonical_json(&plan).as_bytes())
                .to_hex()
                .as_str(),
            expected,
            "argument scanning changed the plan for {source}",
        );
    }
}
