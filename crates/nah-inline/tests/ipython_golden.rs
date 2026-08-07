use nah_inline::{
    Evidence, FindingKind, InlineInput, LanguageAnalysis, LanguageCallKind, NestedExecution,
    ProtectionInput, analyze, analyze_with_language_effects,
};
use nah_proto::action::InvocationInput;
use nah_proto::ctx::Platform;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(default = "default_program")]
    program: String,
    code: String,
    expected: Value,
}

fn default_program() -> String {
    "ipython".into()
}

fn language_analysis(code: &str) -> LanguageAnalysis {
    analyze_with_language_effects(
        InlineInput {
            program: "ipython",
            code,
            home: "/home/dev",
            platform: Platform::Linux,
        },
        ProtectionInput {
            critical_paths: &[],
            ambient_variables: &[],
        },
    )
}

fn native_input(input: &InvocationInput) -> (&Value, bool) {
    match input {
        InvocationInput::Native { value, complete } => (value, *complete),
        InvocationInput::Shell { .. } => panic!("IPython calls must retain native evidence"),
    }
}

#[test]
fn frozen_ipython_frontend_cases_match() {
    for line in include_str!("fixtures/ipython.jsonl").lines() {
        let case: Case = serde_json::from_str(line).unwrap();
        let report = analyze(InlineInput {
            program: &case.program,
            code: &case.code,
            home: "/home/dev",
            platform: Platform::Linux,
        });
        let findings = report
            .findings()
            .iter()
            .map(|finding| {
                let kind = match finding.kind() {
                    FindingKind::RootDestruction => "root-destruction",
                    FindingKind::HomeDestruction => "home-destruction",
                    FindingKind::DecodedExecution => "decoded-execution",
                    FindingKind::NahTampering => "nah-tampering",
                };
                let evidence = match finding.evidence() {
                    Evidence::Exact => "exact",
                    Evidence::Conservative => "conservative",
                };
                format!("{kind}:{evidence}")
            })
            .collect::<Vec<_>>();
        let nested_executions = report
            .nested_executions()
            .iter()
            .map(|execution| match execution {
                NestedExecution::Shell {
                    program,
                    code,
                    stdout_inherited,
                } => json!({
                    "kind":"shell",
                    "program":program,
                    "code":code,
                    "stdout_inherited":stdout_inherited
                }),
                NestedExecution::Command {
                    argv,
                    stdout_inherited,
                } => json!({
                    "kind":"command",
                    "argv":argv,
                    "stdout_inherited":stdout_inherited
                }),
            })
            .collect::<Vec<_>>();
        let refusals = report
            .refusals()
            .iter()
            .map(|refusal| refusal.code())
            .collect::<Vec<_>>();
        assert_eq!(
            json!({
                "findings":findings,
                "nested_executions":nested_executions,
                "refusals":refusals
            }),
            case.expected,
            "{}",
            case.id
        );
    }
}

#[test]
fn exact_shell_forms_emit_nested_execution_and_canonical_draft_evidence() {
    for (source, callable, positional, program, code, stdout_inherited) in [
        (
            "!printf visible",
            "ipython.system",
            json!([{"kind":"string","value":"printf visible"}]),
            "sh",
            "printf visible",
            true,
        ),
        (
            "!!printf captured",
            "ipython.getoutput",
            json!([{"kind":"string","value":"printf captured"}]),
            "sh",
            "printf captured",
            false,
        ),
        (
            "%%bash\nprintf bash",
            "ipython.run_cell_magic",
            json!([
                {"kind":"string","value":"bash"},
                {"kind":"string","value":""},
                {"kind":"string","value":"printf bash"},
            ]),
            "bash",
            "printf bash",
            true,
        ),
        (
            "%%sh\nprintf sh",
            "ipython.run_cell_magic",
            json!([
                {"kind":"string","value":"sh"},
                {"kind":"string","value":""},
                {"kind":"string","value":"printf sh"},
            ]),
            "sh",
            "printf sh",
            true,
        ),
    ] {
        let analysis = language_analysis(source);
        assert!(analysis.draft().complete(), "{source}");
        let [call] = analysis.draft().calls() else {
            panic!("expected one canonical call for {source}");
        };
        assert_eq!(call.kind(), LanguageCallKind::EvaluatedShell, "{source}");
        assert_eq!(
            native_input(call.input()),
            (
                &json!({
                    "v":1,
                    "language":"python",
                    "callable":callable,
                    "positional":positional,
                    "keywords":[],
                }),
                true,
            ),
            "{source}"
        );
        assert!(matches!(
            analysis.report().nested_executions(),
            [NestedExecution::Shell {
                program: nested_program,
                code: nested,
                stdout_inherited: inherited,
            }] if nested_program == program
                && nested == code
                && *inherited == stdout_inherited
        ));
    }
}

#[test]
fn opaque_and_incomplete_forms_are_partial_without_fabricated_effects() {
    for source in [
        "target='/'\n!rm -rf {target}",
        "target='/'\n!rm -rf $target",
        "if True:\n    !rm -rf /",
        "value = (\n!rm -rf /\n)",
        "%custom rm -rf /",
        "!rm -rf /\nvalue = @",
        "plugin()\n!rm -rf /",
    ] {
        let analysis = language_analysis(source);
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }
}

#[test]
fn run_stays_partial_until_the_draft_can_represent_interpreter_file_execution() {
    for source in [
        "%run /tmp/task.py",
        "%run -i /tmp/task.py",
        "%run {task}",
        "%run /tmp/one.py /tmp/two.py",
    ] {
        let analysis = language_analysis(source);
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }
}

#[test]
fn magic_text_in_strings_and_comments_stays_inert() {
    let analysis = language_analysis(
        "text='!rm -rf / %run /tmp/task.py'\n# %%bash\nimport os\nos.remove('/tmp/exact')",
    );
    let [call] = analysis.draft().calls() else {
        panic!("expected only the Python call");
    };
    assert_eq!(call.kind(), LanguageCallKind::DirectFile);
    assert_eq!(call.filesystems()[0].requested(), Some("/tmp/exact"));
    assert!(analysis.draft().complete());
    assert!(analysis.report().nested_executions().is_empty());
}
