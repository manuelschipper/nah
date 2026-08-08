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
                    ..
                } => json!({
                    "kind":"shell",
                    "program":program,
                    "code":code,
                    "stdout_inherited":stdout_inherited
                }),
                NestedExecution::Command {
                    argv,
                    stdout_inherited,
                    ..
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
                ..
            }] if nested_program == program
                && nested == code
                && *inherited == stdout_inherited
        ));
    }
}

#[test]
fn direct_get_ipython_needs_an_observed_bash() {
    for (source, shell) in [
        ("get_ipython().system('printf unknown')", None),
        ("get_ipython().system('printf sh')", Some("/bin/sh")),
        ("get_ipython().system('printf zsh')", Some("/bin/zsh")),
    ] {
        let analysis = language_analysis_with_shell(source, shell);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(matches!(
            analysis.draft().calls(),
            [call] if call.kind() == LanguageCallKind::EvaluatedShell
        ));
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }

    let sh_cell = language_analysis_with_shell("%%sh\nprintf cell", Some("/bin/bash"));
    assert!(sh_cell.draft().complete());
    assert!(matches!(
        sh_cell.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }]
            if program == "sh" && code == "printf cell\n"
    ));
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

    for mutation in [
        "sys.modules.clear()",
        "sys.modules['shutil'] = replacement",
        "setattr(sys, 'modules', {})",
        "sys.__dict__['modules'] = {}",
        "registry = sys.modules\nregistry |= {}",
        "box = [sys.modules]\nbox[0]['shutil'] = replacement",
        "registry = sys.__dict__['modules']\nregistry['shutil'] = replacement",
    ] {
        let source = format!("import sys\n{mutation}\nget_ipython().system('printf host-owned')");
        let analysis = language_analysis(&source);
        assert!(matches!(
            analysis.report().nested_executions(),
            [NestedExecution::Shell { program, code, .. }]
                if program == "bash" && code == "printf host-owned"
        ));
        assert!(!analysis.draft().complete());
    }

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
fn persistent_kernel_owns_reviewed_current_cell_evidence() {
    for (source, expected_path) in [
        ("open('/tmp/current-open', 'w')", "/tmp/current-open"),
        (
            "import os\nos.remove('/tmp/current-module')",
            "/tmp/current-module",
        ),
        (
            "from os import remove\nremove('/tmp/current-from')",
            "/tmp/current-from",
        ),
        (
            "getattr(__import__('os'), 'remove')('/tmp/current-getattr')",
            "/tmp/current-getattr",
        ),
        (
            "eval(\"open('/tmp/current-eval', 'w')\")",
            "/tmp/current-eval",
        ),
        (
            "exec(\"open('/tmp/current-exec', 'w')\")",
            "/tmp/current-exec",
        ),
        (
            "eval(compile(\"open('/tmp/current-compile', 'w')\", '<cell>', 'exec'))",
            "/tmp/current-compile",
        ),
    ] {
        let analysis = persistent_language_analysis(source);
        let [call] = analysis.draft().calls() else {
            panic!("expected one current-cell call for {source}");
        };
        assert_eq!(call.filesystems()[0].requested(), Some(expected_path));
        assert!(analysis.draft().complete(), "{source}");
    }
}

#[test]
fn persistent_kernel_owns_current_cell_process_and_http_sinks() {
    let analysis = persistent_language_analysis(
        "import subprocess\nsubprocess.run(['rm', '-rf', '/tmp/current-argv'])",
    );
    let [call] = analysis.draft().calls() else {
        panic!("expected the current-cell subprocess call");
    };
    assert_eq!(call.kind(), LanguageCallKind::LocalUtility);
    assert_eq!(native_input(call.input()).0["callable"], "subprocess.run");
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv == &["rm", "-rf", "/tmp/current-argv"]
    ));
    assert!(analysis.draft().complete());

    let analysis = persistent_language_analysis(
        "import subprocess\nsubprocess.run('rm -rf /tmp/current-shell', shell=True)",
    );
    let [call] = analysis.draft().calls() else {
        panic!("expected the current-cell subprocess shell call");
    };
    assert_eq!(call.kind(), LanguageCallKind::EvaluatedShell);
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }]
            if program == "sh" && code == "rm -rf /tmp/current-shell"
    ));
    assert!(analysis.draft().complete());

    let analysis = persistent_language_analysis(
        "import requests\nrequests.post('https://example.test/upload', data='visible')",
    );
    let [call] = analysis.draft().calls() else {
        panic!("expected the current-cell HTTP call");
    };
    assert_eq!(call.kind(), LanguageCallKind::NetworkTransfer);
    assert_eq!(call.endpoint(), Some("https://example.test/upload"));
    assert!(analysis.draft().complete());
}

#[test]
fn persistent_kernel_keeps_ambient_state_and_visible_barriers_unknown() {
    for source in [
        "get_ipython().system('rm -rf /tmp/prior-shell')",
        "prior_callable()",
        "prior_object.method()",
        "os.remove('/tmp/prior-module')",
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }

    for source in [
        "open = replacement\nopen('/tmp/rebound-builtin', 'w')",
        "import os\nos.remove = replacement\nos.remove('/tmp/mutated-module')",
        "import os\nconsume(os)\nos.remove('/tmp/escaped-module')",
        "import sys\nsys.modules['os'] = replacement\nimport os\nos.remove('/tmp/replaced-module')",
        "import builtins\nbuiltins.open = replacement\nopen('/tmp/mutated-builtin', 'w')",
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.draft().calls().is_empty(), "{source}");
    }

    let analysis = persistent_language_analysis("import os\nos.remove('relative-target')");
    let [call] = analysis.draft().calls() else {
        panic!("expected the relative call to remain visible");
    };
    assert_eq!(call.filesystems()[0].requested(), None);
    assert!(!analysis.draft().complete());

    let analysis = persistent_language_analysis("def current():\n    return 1\ncurrent()");
    assert!(analysis.draft().complete());
    assert!(analysis.draft().calls().is_empty());
}

#[test]
fn persistent_operational_syntax_does_not_depend_on_get_ipython_ownership() {
    let analysis =
        persistent_language_analysis("%%bash --no-raise-error --noprofile --norc -x\nrm -rf /");
    assert!(!analysis.draft().complete());
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell {
            program,
            code,
            stdout_inherited: true,
            ..
        }] if program == "bash" && code == "rm -rf /\n"
    ));
    assert!(matches!(
        analysis.draft().calls(),
        [call] if call.kind() == LanguageCallKind::EvaluatedShell
            && native_input(call.input()).1
    ));

    for (source, stdout_inherited) in [
        ("target='/'\n!rm -rf {target}", true),
        ("target='/'\n!!rm -rf $target", false),
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(matches!(
            analysis.report().nested_executions(),
            [NestedExecution::Shell {
                program,
                code,
                stdout_inherited: inherited,
                ..
            }] if program == "sh" && code == "rm -rf /" && *inherited == stdout_inherited
        ));
        assert!(matches!(
            analysis.draft().calls(),
            [call] if call.kind() == LanguageCallKind::EvaluatedShell
                && native_input(call.input()).1
        ));
    }

    let analysis = persistent_language_analysis("%%sh\nrm -rf /");
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }]
            if program == "sh" && code == "rm -rf /\n"
    ));

    let analysis = persistent_language_analysis("plugin()\n!rm -rf /");
    assert!(!analysis.draft().complete());
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }]
            if program == "sh" && code == "rm -rf /"
    ));
}

#[test]
fn raw_source_cannot_invoke_or_replace_preprocessing_intrinsics() {
    for source in [
        "__nah_ipython_system_7f19__('rm -rf /')",
        "__nah_ipython_getoutput_7f19__('rm -rf /')",
        "__nah_ipython_cell_7f19__('bash', '', 'rm -rf /')",
        "__nah_ipython_system_7f19__ = replacement\n!rm -rf /",
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }
}

#[test]
fn exact_current_cell_interpolation_reaches_the_observed_bash() {
    for (source, expected, stdout_inherited) in [
        ("target='/'\n!rm -rf {target}", "rm -rf /", true),
        ("target='/'\n!!rm -rf $target", "rm -rf /", false),
        ("!printf '$target'", "printf '$target'", true),
        ("!printf $$HOME", "printf $HOME", true),
    ] {
        let analysis = language_analysis(source);
        assert!(analysis.draft().complete(), "{source}");
        assert!(matches!(
            analysis.report().nested_executions(),
            [NestedExecution::Shell {
                program,
                code,
                stdout_inherited: inherited,
                ..
            }] if program == "bash" && code == expected && *inherited == stdout_inherited
        ));
    }

    for source in ["!rm -rf {prior}", "!rm -rf $prior", "!rm -rf $prior.value"] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(analysis.report().nested_executions().is_empty(), "{source}");
    }
}

#[test]
fn transparent_time_and_capture_cells_preserve_body_effects() {
    for source in [
        "%%time\n%%bash --noprofile\nrm -rf /",
        "%%capture\n%%bash --norc\nrm -rf /",
    ] {
        let analysis = persistent_language_analysis(source);
        assert!(!analysis.draft().complete(), "{source}");
        assert!(matches!(
            analysis.report().nested_executions(),
            [NestedExecution::Shell { program, code, .. }]
                if program == "bash" && code == "rm -rf /\n"
        ));
    }

    let analysis = language_analysis("%time import os; os.remove('/tmp/timed')");
    assert!(analysis.draft().complete());
    assert!(matches!(
        analysis.draft().calls(),
        [call] if call.kind() == LanguageCallKind::DirectFile
            && call.filesystems()[0].requested() == Some("/tmp/timed")
    ));
}

#[test]
fn opaque_and_incomplete_forms_are_partial_without_fabricated_effects() {
    for source in [
        "!rm -rf / &",
        "if True:\n    !rm -rf /",
        "value = (\n!rm -rf /\n)",
        "%custom rm -rf /",
        "# comment\n%%bash\nrm -rf /",
        "!rm -rf /\nvalue = @",
        "%%bash -e\nrm -rf /",
        "%%bash -- --noprofile\nrm -rf /",
        "%%bash -x --noprofile\nrm -rf /",
        "%%capture output\n%%bash\nrm -rf /",
        "%%time\n!rm -rf /\nvalue = @",
        "__nah_ipython_system_7f19__ = replacement\n!rm -rf /",
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
