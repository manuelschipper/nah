use super::*;

fn report(code: &str) -> InlineReport {
    interpret(
        "python3",
        &InlineInput {
            program: "python3",
            code,
            home: "/home/dev",
            platform: Platform::Linux,
        },
        None,
        0,
        InitialState::Fresh,
        false,
        false,
    )
    .into_report()
}

fn assert_work_limit(report: &InlineReport) {
    assert!(report.findings().is_empty(), "{report:?}");
    assert!(report.nested_executions().is_empty(), "{report:?}");
    assert_eq!(report.refusals(), [InlineRefusal::WorkLimit]);
}

#[test]
fn constants_branches_loops_and_alias_cells_feed_known_sinks() {
    for code in [
        "import shutil\nbase='/'\nif True:\n    shutil.rmtree(base)",
        "import shutil\nfor target in ['/tmp', '/']:\n    shutil.rmtree(target)",
        "import subprocess\nargv=['rm']\nalias=argv\nalias.extend(['-rf','/'])\nsubprocess.run(argv)",
    ] {
        let report = report(code);
        assert!(
            report.contains_exact(FindingKind::RootDestruction)
                || !report.nested_executions().is_empty(),
            "{code}: {report:?}"
        );
    }
}

#[test]
fn f_strings_paths_and_local_functions_are_bounded_values() {
    let report = report("import os\ndef run(name):\n    os.system(f'printf {name}')\nrun('child')");
    assert!(matches!(
        report.nested_executions(),
        [NestedExecution::Shell { code, .. }] if code == "printf child"
    ));
}

#[test]
fn local_functions_execute_only_after_exact_argument_binding() {
    for code in [
        "import shutil\ndef danger(required):\n    shutil.rmtree('/')\ndanger()",
        "import shutil\ndef danger(value):\n    shutil.rmtree('/')\ndanger(1, 2)",
        "import shutil\ndef danger(value):\n    shutil.rmtree('/')\ndanger(other=1)",
        "import shutil\ndef danger(value):\n    shutil.rmtree('/')\ndanger(1, value=2)",
        "import shutil\ndef danger(*values):\n    shutil.rmtree('/')\ndanger()",
    ] {
        assert_eq!(report(code), InlineReport::default(), "{code}");
    }

    for code in [
        "import shutil\ndef danger(path='/'): shutil.rmtree(path)\ndanger()",
        "import shutil\ndef danger(path): shutil.rmtree(path)\ndanger(path='/')",
        "import shutil\ndef danger(path: str): shutil.rmtree(path)\ndanger('/')",
        "import shutil\ndef invoke(callback, target): callback(target)\nalias=invoke\nalias(shutil.rmtree, '/')",
    ] {
        assert!(
            report(code).contains_exact(FindingKind::RootDestruction),
            "{code}"
        );
    }
}

#[test]
fn function_locals_are_predeclared_without_masking_global_or_attribute_access() {
    for code in [
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    shutil += other\nrun()",
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    import shutil\nrun()",
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    *shutil, = values\nrun()",
        "import shutil as tool\ndef run():\n    tool.rmtree('/')\n    import package as tool\nrun()",
        "from shutil import rmtree\ndef run():\n    rmtree('/')\n    from shutil import rmtree\nrun()",
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    for shutil in []:\n        pass\nrun()",
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    def shutil():\n        pass\nrun()",
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    class shutil:\n        pass\nrun()",
    ] {
        assert_eq!(report(code), InlineReport::default(), "{code}");
    }

    for code in [
        "import shutil\ndef run():\n    shutil.rmtree('/')\n    shutil.member = None\nrun()",
        "import shutil\ndef run():\n    global shutil\n    shutil.rmtree('/')\n    shutil = None\nrun()",
    ] {
        assert!(
            report(code).contains_exact(FindingKind::RootDestruction),
            "{code}"
        );
    }
}

#[test]
fn branch_local_function_indices_do_not_alias_different_bodies() {
    assert_eq!(
        report(
            "import shutil\nif condition:\n    def action(): shutil.rmtree('/')\nelse:\n    def action(): pass\naction()"
        ),
        InlineReport::default()
    );
    assert_eq!(
        report(
            "import shutil\nif condition:\n    def action(): shutil.rmtree('/')\n    callbacks=[action]\nelse:\n    def action(): pass\n    callbacks=[action]\ncallback,=callbacks\ncallback()"
        ),
        InlineReport::default()
    );
    assert!(
        report(
            "import shutil\ndef action(): shutil.rmtree('/')\nif condition:\n    alias=action\nelse:\n    alias=action\nalias()"
        )
        .contains_exact(FindingKind::RootDestruction)
    );
}

#[test]
fn local_calls_propagate_mutations_to_shared_cells() {
    for code in [
        "import subprocess\nargv=['rm']\nalias=argv\ndef finish(parts): parts.extend(['-rf','/'])\nfinish(alias)\nsubprocess.run(argv)",
        "import subprocess\nargv=['rm']\nalias=argv\ndef finish(parts): parts.extend(['-rf','/'])\nfinish(parts=alias)\nsubprocess.run(argv)",
        "import subprocess\nargv=['rm']\nalias=argv\ndef finish(): alias.extend(['-rf','/'])\nfinish()\nsubprocess.run(argv)",
    ] {
        assert!(matches!(
            report(code).nested_executions(),
            [NestedExecution::Command { argv, .. }] if argv == &["rm", "-rf", "/"]
        ));
    }

    assert!(report(
        "import subprocess\nargv=['rm']\ndef finish(parts): parts.extend(['-rf','/'])\nfinish()\nsubprocess.run(argv)"
    )
    .nested_executions()
    .is_empty());

    let mut code = "items=['x']\ndef grow(values):\n".to_owned();
    for _ in 0..9 {
        code.push_str("    values.extend(values)\n");
    }
    code.push_str("grow(items)");
    assert_work_limit(&report(&code));
}

#[test]
fn unknown_calls_and_rebound_owners_do_not_invent_effects() {
    for code in [
        "shutil.rmtree('/')",
        "import shutil\nshutil=safe\nshutil.rmtree('/')",
        "command=plugin.make(user)\nimport os\nos.system(command)",
    ] {
        assert_eq!(report(code), InlineReport::default(), "{code}");
    }
}

#[test]
fn sys_modules_mutation_and_escape_remove_import_ownership() {
    for code in [
        "import sys\nsys.modules['shutil'] = replacement\nimport shutil\nshutil.rmtree('/')",
        "import sys as runtime\nregistry = runtime.modules\nregistry['shutil'] = replacement\nimport shutil\nshutil.rmtree('/')",
        "from sys import modules as registry\ndel registry['shutil']\nimport shutil\nshutil.rmtree('/')",
        "import sys\nmutate = sys.modules.clear\nmutate()\nimport shutil\nshutil.rmtree('/')",
        "from sys import modules\nmodules.update({})\nimport shutil\nshutil.rmtree('/')",
        "import sys\nconsume(sys.modules)\nimport shutil\nshutil.rmtree('/')",
        "import sys\nsetattr(sys, 'modules', {})\nimport shutil\nshutil.rmtree('/')",
        "import sys\nsys.__dict__['modules'] = {}\nimport shutil\nshutil.rmtree('/')",
        "import sys\nregistry = sys.modules\nregistry |= {}\nimport shutil\nshutil.rmtree('/')",
        "import sys\nbox = [sys.modules]\nbox[0]['shutil'] = replacement\nimport shutil\nshutil.rmtree('/')",
        "import sys\nregistry = sys.__dict__['modules']\nregistry['shutil'] = replacement\nimport shutil\nshutil.rmtree('/')",
    ] {
        assert_eq!(report(code), InlineReport::default(), "{code}");
    }
}

#[test]
fn read_only_sys_modules_access_keeps_import_ownership() {
    for code in [
        "import sys\nsys.modules['sys']\nimport shutil\nshutil.rmtree('/')",
        "import sys as runtime\nruntime.modules.get('shutil')\nimport shutil\nshutil.rmtree('/')",
        "from sys import modules as registry\nregistry.keys()\nimport shutil\nshutil.rmtree('/')",
    ] {
        assert!(
            report(code).contains_exact(FindingKind::RootDestruction),
            "{code}"
        );
    }
}

#[test]
fn comparisons_follow_operand_order_and_known_false_conditions() {
    assert_eq!(
        report("import shutil\nif 1 != 1:\n    shutil.rmtree('/')"),
        InlineReport::default()
    );
    assert!(
        report("import shutil\nif shutil.rmtree('/') == None:\n    pass")
            .contains_exact(FindingKind::RootDestruction)
    );
}

#[test]
fn path_and_exec_summaries_preserve_runtime_identity() {
    assert_eq!(
        report("import os, shutil\nshutil.rmtree(os.path.abspath('~'))"),
        InlineReport::default()
    );
    assert!(
        report("import os, shutil\nshutil.rmtree(os.path.expanduser('~'))")
            .contains_exact(FindingKind::HomeDestruction)
    );
    assert_eq!(
        report("import os.path, shutil\nshutil.rmtree(os.abspath('~'))"),
        InlineReport::default()
    );
    assert!(matches!(
        report("import os\nos.execl('/bin/echo', 'rm', '-rf', '/')")
            .nested_executions(),
        [NestedExecution::Command { argv, .. }] if argv == &["/bin/echo", "-rf", "/"]
    ));
}

#[test]
fn loop_else_and_iteration_limits_do_not_drop_control_flow() {
    assert!(
        report("import shutil\nfor value in []:\n    pass\nelse:\n    shutil.rmtree('/')")
            .contains_exact(FindingKind::RootDestruction)
    );
    assert_eq!(
        report("import shutil\nfor value in [1]:\n    break\nelse:\n    shutil.rmtree('/')"),
        InlineReport::default()
    );
    assert!(
        report("import shutil\nwhile False:\n    pass\nelse:\n    shutil.rmtree('/')")
            .contains_exact(FindingKind::RootDestruction)
    );
    assert_eq!(
        report("import shutil\nwhile True:\n    break\nelse:\n    shutil.rmtree('/')"),
        InlineReport::default()
    );
    assert!(
        report("import shutil\nwhile condition:\n    break\nelse:\n    shutil.rmtree('/')")
            .contains_exact(FindingKind::RootDestruction)
    );
    assert_eq!(
        report("import shutil\nwhile True:\n    pass\nshutil.rmtree('/')"),
        InlineReport::default()
    );

    let values = (0..64)
        .map(|value| value.to_string())
        .chain(std::iter::once("'/'".to_owned()))
        .collect::<Vec<_>>()
        .join(",");
    let report = report(&format!(
        "import shutil\nfor target in [{values}]:\n    shutil.rmtree(target)"
    ));
    assert!(!report.contains_exact(FindingKind::RootDestruction));
    assert_eq!(report.refusals(), [InlineRefusal::WorkLimit]);
}

#[test]
fn unsupported_boundaries_do_not_execute_nested_calls() {
    for code in [
        "import shutil\n[shutil.rmtree('/') for _ in []]",
        "import shutil\nmatch 0:\n    case 1: shutil.rmtree('/')",
    ] {
        assert_eq!(report(code), InlineReport::default(), "{code}");
    }
}

#[test]
fn dynamic_code_preserves_parse_mode_and_source_identity() {
    assert_eq!(
        report("eval(\"import shutil; shutil.rmtree('/')\")"),
        InlineReport::default()
    );
    for code in [
        "import shutil\neval(\"shutil.rmtree('/')\")",
        "exec(\"import shutil; shutil.rmtree('/')\")",
        "eval(compile(\"import shutil; shutil.rmtree('/')\", '<x>', 'exec'))",
        "source=\"import shutil\\ndef run():\\n    shutil.rmtree('/')\"\nexec(source)\nrun()",
    ] {
        assert!(
            report(code).contains_exact(FindingKind::RootDestruction),
            "{code}"
        );
    }
    assert_eq!(
        report("compile(\"import shutil; shutil.rmtree('/')\", '<x>', 'exec')"),
        InlineReport::default()
    );
    assert_eq!(
        report("eval(\"shutil.rmtree('/')\", 3)"),
        InlineReport::default()
    );
    assert_eq!(
        report("exec(\"import shutil\", {}, {})\nshutil.rmtree('/')"),
        InlineReport::default()
    );
}

#[test]
fn reachability_and_mutation_do_not_reuse_stale_exact_values() {
    for code in [
        "import shutil\nif []:\n    shutil.rmtree('/')",
        "import subprocess\nargv=['rm','-rf','/']\nargv[0]='echo'\nsubprocess.run(argv)",
        "import subprocess\nargv=['rm','-rf','/']\nargv.clear()\nsubprocess.run(argv)",
        "import os\napi=os\nos.system=safe\napi.system('rm -rf /')",
        "import shutil\ntarget='/'\nshutil.rmtree(f'{target!r}')",
        "import shutil\ntry:\n    pass\nexcept:\n    shutil.rmtree('/')",
        "import shutil\ntry:\n    raise RuntimeError()\nelse:\n    shutil.rmtree('/')",
        "import shutil\ndef safe():\n    try:\n        return\n    finally:\n        pass\n    shutil.rmtree('/')\nsafe()",
    ] {
        assert_eq!(report(code), InlineReport::default(), "{code}");
    }
    for code in [
        "import shutil\nclass Config:\n    shutil.rmtree('/')",
        "import shutil\ntry:\n    pass\nfinally:\n    shutil.rmtree('/')",
        "import shutil\ntry:\n    raise RuntimeError()\nexcept:\n    shutil.rmtree('/')",
    ] {
        assert!(
            report(code).contains_exact(FindingKind::RootDestruction),
            "{code}"
        );
    }
}

#[test]
fn exponential_string_bytes_and_dynamic_source_are_bounded() {
    for initial in ["value='x'\n", "value=b'x'\n"] {
        let mut code = initial.to_owned();
        for _ in 0..21 {
            code.push_str("value=value+value\n");
        }
        assert_work_limit(&report(&code));
    }

    let mut code = "source='#x\\n'\n".to_owned();
    for _ in 0..19 {
        code.push_str("source=source+source\n");
    }
    code.push_str("exec(source)");
    assert_work_limit(&report(&code));
}

#[test]
fn collection_mutation_and_splats_respect_the_item_cap() {
    let mut appends = "items=[]\n".to_owned();
    for _ in 0..=MAX_COLLECTION_ITEMS {
        appends.push_str("items.append('x')\n");
    }
    assert_work_limit(&report(&appends));

    let mut extension = "items=['x']\n".to_owned();
    for _ in 0..9 {
        extension.push_str("items.extend(items)\n");
    }
    assert_work_limit(&report(&extension));

    let first = std::iter::repeat_n("'x'", 200)
        .collect::<Vec<_>>()
        .join(",");
    let second = std::iter::repeat_n("'x'", 100)
        .collect::<Vec<_>>()
        .join(",");
    let splat = format!("first=[{first}]\nsecond=[{second}]\ncombined=[*first,*second]");
    assert_work_limit(&report(&splat));
}

#[test]
fn dynamic_source_and_nested_value_bytes_are_checked_before_use() {
    let input = InlineInput {
        program: "python3",
        code: "",
        home: "/home/dev",
        platform: Platform::Linux,
    };
    let mut interpreter = Interpreter {
        program: "python3",
        source: Arc::from(""),
        root_source: Arc::from(""),
        input,
        report: InlineReport::default(),
        budget: Budget::default(),
        complete: true,
        draft: LanguageDraft::default(),
        conditional_depth: 0,
        execution_dominators: Vec::new(),
        call_stack: Vec::new(),
        pending_control: None,
        initial_state: InitialState::Fresh,
        ipython_syntax: false,
        ipython_capture: false,
    };
    interpreter.dynamic_execution(
        Value::String("#".repeat(crate::SOURCE_LIMIT + 1)),
        CodeMode::Exec,
        &mut State::default(),
        0,
    );
    assert_eq!(interpreter.report.refusals(), [InlineRefusal::SourceLimit]);

    let large = "x".repeat(MAX_VALUE_BYTES / 2 + 1);
    let mut budget = Budget::default();
    assert!(join_path(large.clone(), &large, &mut budget).is_none());
    assert_eq!(budget.refusal, Some(InlineRefusal::WorkLimit));

    let values = [Value::String(large.clone()), Value::String(large)];
    let mut budget = Budget::default();
    assert!(bounded_strings(values.iter().map(value_string), &mut budget).is_none());
    assert_eq!(budget.refusal, Some(InlineRefusal::WorkLimit));
}
