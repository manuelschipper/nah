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
            "582b2487872d8bc9046cc8764b88a817c924b37a0b8f3c08286d500ffe7bf670",
        ),
        (
            r#"sudo --userx rm /x"#,
            "0a688d1d8366e7d40dacb2289095c3c261c62bb529b9a94a70c494df5e2edc27",
        ),
        (
            r#"nice --adjustmentx rm /x"#,
            "7c22f27df59d4e60ec136fe1d69b695d9f679b3825187c6445807410eb12be17",
        ),
        (
            r#"rsync -- -a host:/b"#,
            "afd6da4ec6d2e78e491dffeaca556c09d79afa6a3270a6a3d1c948a856659bd9",
        ),
        (
            r#"git checkout -f x -- --"#,
            "d11914bfdf89bf8cb7e43a2aa2ecd86ca5e24df8aa15987909ac794bbaead489",
        ),
        (
            r#"git --"$F" rm x"#,
            "6f4539e0601e62cd07385c16fb36e54b9955ac965f84c4a101a779329afd0333",
        ),
        (
            r#"doas --"$F" rm -rf /x"#,
            "18c84b717cf3fd72b3b79cadd40164946b2ba7afdd0c791414d99d0895b1e009",
        ),
        (
            r#"nice --"$F" rm /x"#,
            "255e649792477f46ce100440245073b679abd9784249ef4f9c97bc5e209db284",
        ),
        (
            r#"nohup --"$F" rm /x"#,
            "de8782d73406f894c441aa37db46ac20da0815f5c47bf65124e5a63ae371eab0",
        ),
        (
            r#"setsid --"$F" rm /x"#,
            "fc500a2ebe0789a91cd0084abf8ba25ba272180db3c87f2b379814003ebb0d3a",
        ),
        (
            r#"stdbuf --"$F" rm /x"#,
            "3453344f069373d87597dabe1f74f99be0f17e1e0131e24ba2d2f061cb5259d5",
        ),
        (
            r#"timeout --"$F" 3 rm /x"#,
            "7146a7483ad42bd37ea379678e0c99d7d0d9755999aae1f474dab7b4e15068b6",
        ),
        (
            r#"env --"$F" rm /x"#,
            "5bac5cb2d3f8f8298bfd105b88772c676feaa6c7212d48e16e238b15e5febff4",
        ),
        (
            r#"sshpass --"$F" ssh host rm /x"#,
            "09e50e8b9ea92a660a14d2770ac1972e864c65bccc01643c1f20a5e64c982fa6",
        ),
        (
            r#"runuser -c"$C" root rm /x"#,
            "fa4ed99e48dd288c98e75bf1e97603125d8c2398aa2c468754cc4ec336beb88b",
        ),
        (
            r#"runuser -u -c"$C" root rm /x"#,
            "9e91f3c8fe0aa4851066d749e21c83103ccdfff3803ece4b3f60c357f377af4c",
        ),
        (
            r#"runuser -fl root rm /x"#,
            "1700952cf278c5befeb9b37680764da7a6d4a3fe89f3d1f5a9dd2ce2dbfbbbc5",
        ),
        (
            r#"su --user= root -c "rm /x""#,
            "df3487b44851aa770221fff7d629ddb2aeb070d0554598f308d54196058189d7",
        ),
        (
            r#"docker exec - box rm /x"#,
            "f9163c070ee79e9a507133f67a1b5a89eba356cc519815efc6a6618c4244afc1",
        ),
        (
            r#"docker build - ."#,
            "d113ffde5460c31da898d5b57fde85d2853c5892e1bfc2322a9cdf622ce9f642",
        ),
        (
            r#"docker run - alpine rm /x"#,
            "80b950e5c496f0243eee184c3a61b40e767e3921feed8fe2252ca87bc281dbab",
        ),
        (
            r#"docker --"$F" run alpine rm /x"#,
            "38c2f1463ba836ebe9cce704801d21341ec4bae64f5688696393b14d0dc84986",
        ),
        (
            r#"git push --"$F" origin main"#,
            "079d83045bc17a1803a5048ce3cc30d22addb0e0e4b63d1f492f9e3e10dafe16",
        ),
        (
            r#"wipefs --"$F" -a /dev/x"#,
            "b358270704e11517581a6abd81f889fe3910cf484e27cf482e06a8476db026eb",
        ),
        (
            r#"git rm x --"$F""#,
            "9f2aa51e9edfa36516dbd1e5c74a390808030fd19a97db985a33b9de43e0a38e",
        ),
        (
            r#"rsync a host:/b -- --"#,
            "9ea1d4dd7135d267c44b81804911f2bdc438fe3b7e17ac3961bc30cb0a0cf96e",
        ),
        (
            r#"scp a host:/b -- --"#,
            "4ecfdf4aa6e787444bd652d57972d5b0d825ec6f3671a8e7bc77921ceada8c80",
        ),
        (
            r#"rsync --"$F" a host:/b"#,
            "2aaa3d1ad73332a0a2180b33e10454155d8612279345e1b04a3b49d1651acfff",
        ),
        (
            r#"scp --"$F" a host:/b"#,
            "186089942a06b664461344f7339a631afd141d18031676cd540e1d6839eadc2a",
        ),
        (
            r#"aws -- -- s3 cp a s3://bucket/b"#,
            "260e566c9b45901c9d991c3c1001f115ba7d7f7109c5a9c6655d67ce69af86e5",
        ),
        (
            r#"gcloud -- -- storage cp a gs://bucket/b"#,
            "188d539014676e4dc6fe1cea2a10b412d96f429c5e1c395541820d1c9f497980",
        ),
        (
            r#"nats -- -- pub topic msg"#,
            "8c5c238e0859ed1189f64894ac080ee6ca212b91f4b411e89e6105bab72b4193",
        ),
        (
            r#"rabbitmqadmin -- -- delete queue name=q"#,
            "bccf50878bada5cba60710796726be37d8352b7de5c1d1baf7a6651e7ca53087",
        ),
        (
            r#"redis-cli -- -- DEL k"#,
            "05c8bfa7aa082f957cc39cafd68acfd8913b5e5587830ec4b044451980015037",
        ),
        (
            r#"git reset -- --hard"#,
            "0ed5965cafd2005a2fe20e63d6e82fdd89bbed11f3b04cb61a919792bf5a5f3b",
        ),
        (
            r#"git - rm x"#,
            "eff0f9747f76d154da89687a5cb7c2877285cee4a713713ae28e6d87934cf233",
        ),
        (
            r#"psql -c --"$F" "DELETE FROM x""#,
            "17cfa1b5137ef723583571b867cd7050d4db2b736b1ce502f73dcb27f3f15660",
        ),
        (
            r#"psql --command="$C" -c "DELETE FROM x""#,
            "d45275ed1ff4e9d03a998f67e552afc3835ade03375ed706cf0e2cccb6a063e7",
        ),
        (
            r#"mysql -e --"$F" "DELETE FROM x""#,
            "6ea426ed2b2149b012fb73a57587c7bda54a6ae81338d9cd237d6ffac851c880",
        ),
        (
            r#"wipefs -za /dev/x"#,
            "a2dda1303b10c09e834eea17b3b5cd16921301f8cca3ebf34d8fa9f0b7904b82",
        ),
        (
            r#"gzip -zk x"#,
            "4b05b5f8ddd37bb084ae2ee7b442322baaff2e06a01e5c1e5cff02b4933ae11a",
        ),
        (
            r#"wipefs --all=x /dev/x"#,
            "05005b8a593b0295baddfe5240ef5f5fd4fa57454211a49517089994eb87e3f8",
        ),
        (
            r#"gzip --stdout=x x"#,
            "593cfe575e29f1f497fb946bc4c46089fec8b2b8c08a0c25051605a81850aadb",
        ),
        (
            r#"git push -of origin main"#,
            "c3fbf137757296aa3eacb7917222678be880b4d1c28a8ef13780e7e6fd9a1272",
        ),
        (
            r#"rsync a host:/b -- --rsync-path="rm /x""#,
            "3a5a6585a30b06f7b639359d595cbab1d39650ab3732ff7ee60089b7414fffc8",
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
