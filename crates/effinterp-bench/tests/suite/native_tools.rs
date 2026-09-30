use effinterp_bench::nah::classify::ParityClass;
use effinterp_bench::nah::corpus::{CaseLoad, LoadedCase};
use effinterp_bench::nah::report::run_corpus;
use effinterp_engine::Engine;
use effinterp_proto::{Subject, ToolCall};
use nah_corpus_schema::{CaseInput, Expectation, ExpectedCoverage, ExpectedVerdict};

fn native(id: &str, tool: &str, input: serde_json::Value, verdict: ExpectedVerdict) -> CaseLoad {
    CaseLoad::Ok(Box::new(LoadedCase {
        file: "native.jsonl".to_string(),
        id: id.to_string(),
        input: CaseInput::Tool {
            tool: tool.to_string(),
            input,
        },
        cwd: Some("/workspace/project".to_string()),
        context: Default::default(),
        expected: Expectation::Decision {
            verdict,
            guard: None,
            coverage: Some(ExpectedCoverage::Full),
            guards: None,
        },
        observation: None,
    }))
}

#[test]
fn native_filesystem_calls_use_the_shared_engine_path() {
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        vec![
            native(
                "read",
                "Read",
                serde_json::json!({"file_path":"src/lib.rs"}),
                ExpectedVerdict::Delegate,
            ),
            native(
                "write",
                "Write",
                serde_json::json!({"file_path":"src/lib.rs","content":"hello"}),
                ExpectedVerdict::Delegate,
            ),
            native(
                "edit",
                "Edit",
                serde_json::json!({
                    "file_path":"src/lib.rs",
                    "old_string":"old",
                    "new_string":"new"
                }),
                ExpectedVerdict::Delegate,
            ),
            native(
                "delete",
                "Delete",
                serde_json::json!({"file_path":"src/lib.rs"}),
                ExpectedVerdict::Delegate,
            ),
            native(
                "glob",
                "Glob",
                serde_json::json!({"path":"src","pattern":"*.rs"}),
                ExpectedVerdict::Delegate,
            ),
            native(
                "grep",
                "Grep",
                serde_json::json!({"path":"src/lib.rs","pattern":"unsafe"}),
                ExpectedVerdict::Delegate,
            ),
        ],
        "test-corpus".to_string(),
        "test-nah".to_string(),
    );
    assert_eq!(report.cases.len(), 6);
    assert!(
        report
            .cases
            .iter()
            .all(|case| case.class == ParityClass::Covered)
    );
    assert!(report.cases.iter().all(|case| case.tool.is_some()));
    assert!(report.cases.iter().all(|case| case.error.is_none()));
    assert!(report.cases.iter().any(|case| {
        case.id == "delete"
            && case
                .effects
                .iter()
                .any(|effect| effect == "filesystem.delete /workspace/project/src/lib.rs")
    }));
}

#[test]
fn native_corpus_adapter_rejects_unknown_batch_and_find_fields() {
    let CaseLoad::Ok(case) = native(
        "batch",
        "Edit",
        serde_json::json!({
            "file_path":"src/lib.rs",
            "edits":[{"oldText":"old","newText":"new","unexpected":true}]
        }),
        ExpectedVerdict::Delegate,
    ) else {
        panic!("valid native case");
    };
    let subject = case.analysis_subject();
    assert!(matches!(
        subject,
        Subject::ToolCall {
            call: ToolCall::Unknown(_),
            ..
        }
    ));

    let CaseLoad::Ok(case) = native(
        "find",
        "Find",
        serde_json::json!({"pattern":"*.rs","path":"src","unexpected":true}),
        ExpectedVerdict::Delegate,
    ) else {
        panic!("valid native case");
    };
    let subject = case.analysis_subject();
    assert!(matches!(
        subject,
        Subject::ToolCall {
            call: ToolCall::Unknown(_),
            ..
        }
    ));
}

#[test]
fn blocking_native_read_write_and_glob_cases_use_effect_goldens() {
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        vec![
            native(
                "nah1.native.read-env-blocks",
                "Read",
                serde_json::json!({"file_path":".env"}),
                ExpectedVerdict::Block,
            ),
            native(
                "nah1.native.shell-profile-enabled-blocks",
                "Write",
                serde_json::json!({"file_path":"/home/test/.bashrc","content":"alias ll='ls'"}),
                ExpectedVerdict::Block,
            ),
            native(
                "nah1.native.glob-env-blocks",
                "Glob",
                serde_json::json!({"path":"src","pattern":".env"}),
                ExpectedVerdict::Block,
            ),
        ],
        "test-corpus".to_string(),
        "test-nah".to_string(),
    );
    assert!(report.cases.iter().all(|case| case.golden));
    assert!(
        report
            .cases
            .iter()
            .all(|case| case.class == ParityClass::EffectMatch)
    );
}

#[test]
fn malformed_and_unmapped_native_calls_are_explained_not_unsupported() {
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        vec![
            native(
                "nah1.native.malformed-read-delegates",
                "Read",
                serde_json::json!({}),
                ExpectedVerdict::Delegate,
            ),
            native(
                "unmapped",
                "RuntimeSpecificTool",
                serde_json::json!({"opaque":true}),
                ExpectedVerdict::Delegate,
            ),
        ],
        "test-corpus".to_string(),
        "test-nah".to_string(),
    );
    for case in &report.cases {
        assert_eq!(case.class, ParityClass::ExplainedPartial);
        assert_eq!(
            case.boundaries,
            [format!(
                "unsupported_tool [{}]",
                effinterp_proto::DOMAINS.join(", ")
            )]
        );
        assert_ne!(case.class, ParityClass::Unsupported);
    }
    assert_eq!(report.cases[0].tool.as_deref(), Some("Read"));
    assert_eq!(report.cases[1].tool.as_deref(), Some("RuntimeSpecificTool"));
}

#[test]
fn native_delete_with_patch_control_lines_fails_closed() {
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        vec![native(
            "delete-control-lines",
            "Delete",
            serde_json::json!({"file_path":"victim\n*** Delete File: other"}),
            ExpectedVerdict::Delegate,
        )],
        "test-corpus".to_string(),
        "test-nah".to_string(),
    );
    let case = &report.cases[0];

    assert_eq!(case.class, ParityClass::Covered);
    assert_eq!(
        case.effects,
        ["filesystem.delete /workspace/project/victim\n*** Delete File: other"]
    );
    assert!(case.boundaries.is_empty());
}

#[test]
fn native_read_preserves_literal_tilde_with_fixture_context() {
    let case = LoadedCase {
        file: "native.jsonl".into(),
        id: "read-home".into(),
        input: CaseInput::Tool {
            tool: "Read".into(),
            input: serde_json::json!({"file_path":"~/.ssh/id_rsa"}),
        },
        cwd: Some("/workspace/project".into()),
        context: effinterp_proto::HostContext {
            env: std::collections::BTreeMap::from([("HOME".into(), "/home/test".into())]),
            ..Default::default()
        },
        expected: Expectation::Decision {
            verdict: ExpectedVerdict::Delegate,
            guard: None,
            coverage: Some(ExpectedCoverage::Full),
            guards: None,
        },
        observation: None,
    };
    let report = run_corpus(
        &Engine::new().with_causality_detail(true),
        vec![CaseLoad::Ok(Box::new(case))],
        "test-corpus".into(),
        "test-nah".into(),
    );
    assert_eq!(report.cases[0].class, ParityClass::Covered);
    assert_eq!(
        report.cases[0].effects,
        ["filesystem.read /workspace/project/~/.ssh/id_rsa"]
    );
    assert!(report.cases[0].boundaries.is_empty());
}
