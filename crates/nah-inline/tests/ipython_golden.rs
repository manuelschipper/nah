use nah_inline::{
    Evidence, FindingKind, InlineInput, LanguageAnalysis, LanguageCallKind, NestedExecution,
    ProtectionInput, analyze, analyze_persistent_ipython_with_language_effects,
    analyze_with_language_effects,
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
    language_analysis_with_shell(code, Some("/bin/bash"))
}

fn language_analysis_with_shell(code: &str, shell: Option<&str>) -> LanguageAnalysis {
    let ambient_variables = shell
        .map(|shell| {
            vec![(
                "SHELL".to_owned(),
                nah_inline::EnvironmentValue::Static(shell.to_owned()),
            )]
        })
        .unwrap_or_default();
    analyze_with_language_effects(
        InlineInput {
            program: "ipython",
            code,
            home: "/home/dev",
            platform: Platform::Linux,
        },
        ProtectionInput {
            critical_paths: &[],
            ambient_variables: &ambient_variables,
        },
    )
}

fn persistent_language_analysis(code: &str) -> LanguageAnalysis {
    analyze_persistent_ipython_with_language_effects(
        InlineInput {
            program: "ipython",
            code,
            home: "/home/dev",
            platform: Platform::Linux,
        },
        ProtectionInput {
            critical_paths: &[],
            ambient_variables: &[(
                "SHELL".to_owned(),
                nah_inline::EnvironmentValue::Static("/bin/bash".to_owned()),
            )],
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
            "bash",
            "printf visible",
            true,
        ),
        (
            "!!printf captured",
            "ipython.getoutput",
            json!([{"kind":"string","value":"printf captured"}]),
            "bash",
            "printf captured",
            false,
        ),
        (
            "%%bash\nprintf bash",
            "ipython.run_cell_magic",
            json!([
                {"kind":"string","value":"bash"},
                {"kind":"string","value":""},
                {"kind":"string","value":"printf bash\n"},
            ]),
            "bash",
            "printf bash\n",
            true,
        ),
        (
            " \n\n  %%bash\n    printf indented",
            "ipython.run_cell_magic",
            json!([
                {"kind":"string","value":"bash"},
                {"kind":"string","value":""},
                {"kind":"string","value":"  printf indented\n"},
            ]),
            "bash",
            "  printf indented\n",
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
fn non_bash_or_unobserved_shells_keep_canonical_partial_evidence() {
    for (source, shell) in [
        ("!printf unknown", None),
        ("!printf sh", Some("/bin/sh")),
        ("!printf zsh", Some("/bin/zsh")),
        ("%%sh\nprintf cell", Some("/bin/bash")),
    ] {
        let analysis = language_analysis_with_shell(source, shell);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(matches!(
            analysis.draft().calls(),
            [call] if call.kind() == LanguageCallKind::EvaluatedShell
        ));
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }
}

#[test]
fn get_ipython_ownership_is_exact_until_the_object_escapes_or_is_mutated() {
    let analysis = language_analysis("get_ipython().system('printf direct')");
    assert!(analysis.draft().complete());
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }]
            if program == "bash" && code == "printf direct"
    ));

    for source in [
        "get_ipython = replacement\nget_ipython().system('rm -rf /')",
        "del get_ipython\nget_ipython().system('rm -rf /')",
        "get_ipython().system = replacement\nget_ipython().system('rm -rf /')",
        "shell = get_ipython()\nshell.system('rm -rf /')",
    ] {
        let analysis = language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }
}

#[test]
fn persistent_kernel_state_requires_current_cell_ownership() {
    for source in [
        "open('/tmp/prior-builtin', 'w')",
        "get_ipython().system('rm -rf /tmp/prior-shell')",
        "prior_callable()",
        "prior_object.method()",
        "!rm -rf /tmp/prior-shell",
        "from IPython import get_ipython\n!rm -rf /tmp/current-import-shell",
        "from IPython import get_ipython\n!!rm -rf /tmp/current-import-shell",
        "%%bash\nrm -rf /tmp/rewritten-cell",
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }

    for source in [
        "import os\nos.remove('/tmp/current-import')",
        "from builtins import open\nopen('/tmp/current-builtin', 'w')",
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(analysis.draft().complete(), "{source}");
        assert!(matches!(
            analysis.draft().calls(),
            [call] if call.kind() == LanguageCallKind::DirectFile
                && call.filesystems()[0].requested().is_some_and(|path| path.starts_with("/tmp/"))
        ));
    }

    let analysis = persistent_language_analysis("def current():\n    return 1\ncurrent()");
    assert!(analysis.draft().complete());
    assert!(analysis.draft().calls().is_empty());
}

#[test]
fn opaque_and_incomplete_forms_are_partial_without_fabricated_effects() {
    for source in [
        "target='/'\n!rm -rf {target}",
        "target='/'\n!rm -rf $target",
        "!rm -rf / &",
        "if True:\n    !rm -rf /",
        "value = (\n!rm -rf /\n)",
        "%custom rm -rf /",
        "# comment\n%%bash\nrm -rf /",
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
