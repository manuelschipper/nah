use nah_inline::{
    InlineInput, LanguageAnalysis, LanguageCall, LanguageCallKind, NestedExecution,
    NestedExecutionCwd, ProtectionInput, interpret_language_effects,
};
use nah_proto::{action::FilesystemOperation, ctx::Platform};

fn analyze(program: &str, code: &str) -> LanguageAnalysis {
    interpret_language_effects(
        InlineInput {
            program,
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

fn callable(call: &LanguageCall) -> &str {
    let nah_proto::action::InvocationInput::Native { value, .. } = call.input() else {
        panic!("language calls use native evidence")
    };
    value["callable"].as_str().expect("callable string")
}

#[test]
fn runtime_profiles_are_explicit_and_obsolete_names_are_not_supported() {
    for profile in [
        "deno-run-js",
        "deno-run-typescript",
        "deno-run-tsx",
        "deno-eval-js",
        "deno-eval-typescript",
        "deno-eval-tsx",
        "deno-checked-eval-js",
        "deno-checked-eval-typescript",
        "deno-checked-eval-tsx",
        "bun-js",
        "bun-typescript",
        "bun-tsx",
        "bun-shell",
        "openclaw-javascript",
        "openclaw-typescript",
    ] {
        assert!(nah_inline::supports(profile), "{profile}");
    }
    for obsolete in ["deno-js", "deno-typescript", "deno-tsx"] {
        assert!(!nah_inline::supports(obsolete), "{obsolete}");
    }
}

#[test]
fn expression_assembly_keeps_later_runtime_effects() {
    for (code, requested) in [
        ("[...value, Deno.remove('/array')]", "/array"),
        ("({...value, x:Deno.remove('/object')})", "/object"),
        ("`${value}${Deno.remove('/template')}`", "/template"),
        ("({[key]:1, x:Deno.remove('/computed')})", "/computed"),
        ("({[key](){}, x:Deno.remove('/method')})", "/method"),
    ] {
        let analysis = analyze("deno-eval-js", code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        let call = &analysis.draft().calls()[0];
        assert_eq!(call.filesystems()[0].requested(), Some(requested), "{code}");
        assert_eq!(call.conditional_depth(), 1, "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }

    let hole = analyze("deno-eval-js", "[, Deno.remove('/hole')]");
    assert_eq!(hole.draft().calls().len(), 1);
    assert_eq!(hole.draft().calls()[0].conditional_depth(), 0);
    assert!(hole.draft().complete());

    let hole_argument = analyze(
        "deno-eval-js",
        "new Deno.Command('printf', {args:[,'x']}).spawn()",
    );
    assert!(matches!(
        hole_argument.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv.iter().map(String::as_str).eq(["printf", "undefined", "x"])
    ));
    assert!(hole_argument.draft().complete());

    let ordered = analyze(
        "deno-eval-js",
        "[Deno.remove('/before'), ...value, Deno.remove('/after')]",
    );
    assert_eq!(ordered.draft().calls().len(), 2);
    assert_eq!(ordered.draft().calls()[0].conditional_depth(), 0);
    assert_eq!(ordered.draft().calls()[1].conditional_depth(), 1);
    assert!(!ordered.draft().complete());

    let duplicate = analyze(
        "deno-eval-js",
        "({x:Deno.remove('/first'), x:Deno.remove('/second')})",
    );
    assert_eq!(duplicate.draft().calls().len(), 2);
    assert!(duplicate.draft().complete());

    let primitive_spread = analyze("deno-eval-js", "({...null, x:Deno.remove('/primitive')})");
    assert_eq!(primitive_spread.draft().calls().len(), 1);
    assert_eq!(primitive_spread.draft().calls()[0].conditional_depth(), 0);
    assert!(primitive_spread.draft().complete());
}

#[test]
fn expression_assembly_stops_after_later_abrupt_expressions() {
    for code in [
        "[...value, Deno.remove('/kept'), (()=>{throw 1})(), Deno.remove('/tail')]",
        "[...value, Deno.remove('/kept'), (()=>{while(true){}})(), Deno.remove('/tail')]",
        "`${value}${Deno.remove('/kept')}${(()=>{throw 1})()}${Deno.remove('/tail')}`",
    ] {
        let analysis = analyze("deno-eval-js", code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            Some("/kept"),
            "{code}"
        );
        assert_eq!(analysis.draft().calls()[0].conditional_depth(), 1, "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }
}

#[test]
fn call_argument_spreads_preserve_order_and_modality() {
    let unknown_callee = analyze("deno-eval-js", "f(...value, Deno.remove('/x'))");
    assert_eq!(unknown_callee.draft().calls().len(), 1);
    assert_eq!(callable(&unknown_callee.draft().calls()[0]), "Deno.remove");
    assert_eq!(unknown_callee.draft().calls()[0].conditional_depth(), 1);
    assert!(!unknown_callee.draft().complete());

    let known_callee = analyze("bun-js", "Bun.spawn(...value, Bun.write('/later', 'text'))");
    assert_eq!(
        known_callee
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["Bun.write", "Bun.spawn"]
    );
    assert!(
        known_callee
            .draft()
            .calls()
            .iter()
            .all(|call| call.conditional_depth() == 1)
    );
    assert!(!known_callee.draft().complete());

    for code in ["Deno.remove(...['/array'])", "Deno.remove(...'x')"] {
        let analysis = analyze("deno-eval-js", code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(analysis.draft().calls()[0].conditional_depth(), 0, "{code}");
        assert!(analysis.draft().complete(), "{code}");
    }

    let non_iterable = analyze("deno-eval-js", "Deno.remove(...null, Deno.remove('/tail'))");
    assert!(non_iterable.draft().calls().is_empty());
    assert!(non_iterable.draft().complete());

    let ordered = analyze(
        "deno-eval-js",
        "f(Deno.remove('/before'), ...value, Deno.remove('/after'))",
    );
    assert_eq!(ordered.draft().calls().len(), 2);
    assert_eq!(ordered.draft().calls()[0].conditional_depth(), 0);
    assert_eq!(ordered.draft().calls()[1].conditional_depth(), 1);

    let abrupt = analyze(
        "deno-eval-js",
        "f(...value, Deno.remove('/kept'), (()=>{throw 1})(), Deno.remove('/tail'))",
    );
    assert_eq!(abrupt.draft().calls().len(), 1);
    assert_eq!(
        abrupt.draft().calls()[0].filesystems()[0].requested(),
        Some("/kept")
    );
    assert_eq!(abrupt.draft().calls()[0].conditional_depth(), 1);
}

#[test]
fn deno_eval_owns_only_direct_file_apis() {
    let analysis = analyze(
        "deno-eval-typescript",
        "Deno.remove('/tmp/a', {recursive:true});\
         Deno.mkdirSync('/tmp/b', {recursive:true, mode:448});\
         await Deno.readFile('/tmp/c');\
         Deno.readTextFileSync('/tmp/d');\
         await Deno.writeFile('/tmp/e', bytes);\
         Deno.writeTextFileSync('/tmp/f', 'text')",
    );
    assert_eq!(
        analysis
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        [
            "Deno.remove",
            "Deno.mkdirSync",
            "Deno.readFile",
            "Deno.readTextFileSync",
            "Deno.writeFile",
            "Deno.writeTextFileSync",
        ]
    );
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert!(analysis.draft().calls()[0].filesystems()[0].recursive());
    assert_eq!(
        analysis.draft().calls()[1].filesystems()[0].operation(),
        FilesystemOperation::Write
    );
    assert!(analysis.draft().calls()[1].filesystems()[0].recursive());
    assert_eq!(
        analysis.draft().calls()[2].filesystems()[0].operation(),
        FilesystemOperation::Read
    );
}

#[test]
fn deno_command_is_lazy_and_only_exact_consumers_execute() {
    let lazy = analyze(
        "deno-eval-js",
        "const command = new Deno.Command('rm', {args:['-rf', '/tmp/cache']});",
    );
    assert!(lazy.draft().calls().is_empty());
    assert!(lazy.report().nested_executions().is_empty());
    assert!(lazy.draft().complete());

    for consumer in ["spawn", "output", "outputSync"] {
        let code =
            format!("new Deno.Command('rm', {{args:['-rf', '/tmp/cache']}}).{consumer}('ignored')");
        let analysis = analyze("deno-eval-js", &code);
        assert!(matches!(
            analysis.draft().calls(),
            [call] if call.kind() == LanguageCallKind::LocalUtility
                && callable(call) == format!("Deno.Command.{consumer}")
        ));
        assert!(matches!(
            analysis.report().nested_executions(),
            [NestedExecution::Command { argv, .. }]
                if argv.iter().map(String::as_str).eq(["rm", "-rf", "/tmp/cache"])
        ));
    }

    let extracted = analyze(
        "deno-eval-js",
        "const command = new Deno.Command('rm'); const output = command.output; output()",
    );
    assert!(extracted.draft().calls().is_empty());
    assert!(extracted.report().nested_executions().is_empty());
    assert!(extracted.draft().complete());

    let caught_unbound = analyze(
        "deno-eval-js",
        "const command = new Deno.Command('true'); const output = command.output;\
         try { output() } catch { Deno.remove('/tmp/caught') }",
    );
    assert_eq!(caught_unbound.draft().calls().len(), 1);
    assert_eq!(callable(&caught_unbound.draft().calls()[0]), "Deno.remove");
    assert!(caught_unbound.draft().complete());

    let aliased_constructor = analyze(
        "deno-eval-js",
        "const Command = Deno.Command; new Command('rm').output()",
    );
    assert_eq!(aliased_constructor.draft().calls().len(), 1);
    assert!(matches!(
        aliased_constructor.report().nested_executions(),
        [NestedExecution::Command { argv, .. }] if argv == &["rm"]
    ));
    assert!(aliased_constructor.draft().complete());

    let runtime_options = analyze(
        "deno-eval-js",
        "new Deno.Command('true', 7).output();\
         new Deno.Command('printf', {args:'ok', telemetry:true}).spawn();\
         new Deno.Command('true', null).spawn()",
    );
    assert_eq!(runtime_options.draft().calls().len(), 3);
    assert_eq!(runtime_options.report().nested_executions().len(), 3);
    assert!(runtime_options.draft().complete());

    let invalid_output = analyze(
        "deno-eval-js",
        "new Deno.Command('true', null).output(); Deno.remove('/tmp/tail')",
    );
    assert!(invalid_output.draft().calls().is_empty());
    assert!(invalid_output.report().nested_executions().is_empty());
    assert!(invalid_output.draft().complete());

    let stdio = analyze(
        "deno-eval-js",
        "new Deno.Command('rm', {args:['-rf', '/tmp/a'], stdout:'piped', stderr:'null', uid:1, gid:1}).spawn();\
         new Deno.Command('rm', {args:['-rf', '/tmp/b'], stdout:'inherit'}).spawn()",
    );
    assert_eq!(stdio.draft().calls().len(), 2);
    assert!(matches!(
        stdio.report().nested_executions(),
        [
            NestedExecution::Command {
                stdout_inherited: false,
                ..
            },
            NestedExecution::Command {
                stdout_inherited: true,
                ..
            }
        ]
    ));
    assert!(stdio.draft().complete());

    let changed_context = analyze(
        "deno-eval-js",
        "new Deno.Command('rm', {args:['-rf', 'relative'], cwd:'/tmp'}).spawn()",
    );
    assert_eq!(changed_context.draft().calls().len(), 1);
    assert!(matches!(
        changed_context.report().nested_executions(),
        [NestedExecution::Command {
            cwd: NestedExecutionCwd::Path(cwd),
            ..
        }] if cwd == "/tmp"
    ));
    assert!(changed_context.draft().complete());

    let stdio_runtime_shapes = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {stdout:null}).spawn();\
         new Deno.Command('true', {stdout:1}).output();\
         new Deno.Command('true').outputSync()",
    );
    assert_eq!(stdio_runtime_shapes.draft().calls().len(), 3);
    assert!(matches!(
        stdio_runtime_shapes.report().nested_executions(),
        [
            NestedExecution::Command {
                stdout_inherited: true,
                ..
            },
            NestedExecution::Command {
                stdout_inherited: true,
                ..
            },
            NestedExecution::Command {
                stdout_inherited: false,
                ..
            }
        ]
    ));
    assert!(stdio_runtime_shapes.draft().complete());

    let invalid_output_stdio = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {stdout:null}).output(); Deno.remove('/tmp/tail')",
    );
    assert!(invalid_output_stdio.draft().calls().is_empty());
    assert!(invalid_output_stdio.draft().complete());

    let object_like_options = analyze("deno-eval-js", "new Deno.Command('rm', () => {}).spawn()");
    assert_eq!(object_like_options.draft().calls().len(), 1);
    assert!(object_like_options.report().nested_executions().is_empty());
    assert!(!object_like_options.draft().complete());

    let dynamic_commands = analyze(
        "deno-eval-js",
        "new Deno.Command(program).spawn();\
         new Deno.Command('rm', {args}).output()",
    );
    assert_eq!(dynamic_commands.draft().calls().len(), 2);
    assert!(dynamic_commands.report().nested_executions().is_empty());
    assert!(!dynamic_commands.draft().complete());

    for code in [
        "Deno.Command('true'); Deno.remove('/tmp/tail')",
        "const Command=Deno.Command; Command('true'); Deno.remove('/tmp/tail')",
    ] {
        let class_call = analyze("deno-eval-js", code);
        assert!(class_call.draft().calls().is_empty(), "{code}");
        assert!(class_call.report().nested_executions().is_empty(), "{code}");
        assert!(class_call.draft().complete(), "{code}");
    }

    let caught_class_call = analyze(
        "deno-eval-js",
        "try { Deno.Command('true') } catch { Deno.remove('/tmp/caught') }",
    );
    assert_eq!(caught_class_call.draft().calls().len(), 1);
    assert_eq!(
        callable(&caught_class_call.draft().calls()[0]),
        "Deno.remove"
    );
}

#[test]
fn deno_command_reads_mutable_options_and_cwd_when_consumed() {
    for (code, expected_argv, expected_cwd) in [
        (
            "const o={args:['-rf','.'],cwd:'.'}; const c=new Deno.Command('rm',o); o.cwd='/'; c.spawn()",
            &["rm", "-rf", "."][..],
            NestedExecutionCwd::Path("/".into()),
        ),
        (
            "const o={args:['-rf','.'],cwd:'/'}; const c=new Deno.Command('rm',o); o.cwd='.'; c.spawn()",
            &["rm", "-rf", "."][..],
            NestedExecutionCwd::Path(".".into()),
        ),
        (
            "const o={args:['safe'],cwd:'.'}; const c=new Deno.Command('rm',o); o.args=['-rf','/']; c.spawn()",
            &["rm", "-rf", "/"][..],
            NestedExecutionCwd::Path(".".into()),
        ),
        (
            "const o={args:['safe'],cwd:'.'}; const c=new Deno.Command('rm',o); o.args[0]='-rf'; o.args[1]='/'; c.spawn()",
            &["rm", "-rf", "/"][..],
            NestedExecutionCwd::Path(".".into()),
        ),
        (
            "const o={args:['-rf','.'],cwd:'.'}; const alias=o; const c=new Deno.Command('rm',o); alias.cwd='/'; c.spawn()",
            &["rm", "-rf", "."][..],
            NestedExecutionCwd::Path("/".into()),
        ),
        (
            "const o={args:['-rf','.'],cwd:'/'}; const c=new Deno.Command('rm',o); delete o.cwd; c.spawn()",
            &["rm", "-rf", "."][..],
            NestedExecutionCwd::Inherited,
        ),
    ] {
        let analysis = analyze("deno-eval-js", code);
        assert!(
            matches!(
                analysis.report().nested_executions(),
                [NestedExecution::Command { argv, cwd, .. }]
                    if argv.iter().map(String::as_str).eq(expected_argv.iter().copied())
                        && cwd == &expected_cwd
            ),
            "{code}: {analysis:?}"
        );
        assert!(analysis.draft().complete(), "{code}: {analysis:?}");
    }

    let changed_process_cwd = analyze(
        "deno-eval-js",
        "const c=new Deno.Command('find',{args:['.','-delete'],cwd:'.'}); Deno.chdir('/'); c.spawn()",
    );
    assert!(
        matches!(
            changed_process_cwd.report().nested_executions(),
            [NestedExecution::Command { argv, cwd, .. }]
                if argv.iter().map(String::as_str).eq(["find", ".", "-delete"])
                    && cwd == &NestedExecutionCwd::Path("/.".into())
        ),
        "{changed_process_cwd:?}"
    );
    assert!(changed_process_cwd.draft().complete());
}

#[test]
fn runtime_function_constructibility_matches_the_host() {
    let constructible_deno = analyze(
        "deno-eval-js",
        "new Deno.removeSync('/tmp/remove');\
         new Deno.mkdirSync('/tmp/mkdir');\
         new Deno.readTextFileSync('/tmp/read');\
         new Deno.writeTextFileSync('/tmp/write-sync', 'text');\
         new Deno.writeTextFile('/tmp/write', 'text')",
    );
    assert_eq!(constructible_deno.draft().calls().len(), 5);
    assert!(constructible_deno.draft().complete());

    for member in ["remove", "mkdir", "readFile", "readTextFile", "writeFile"] {
        let code = format!("new Deno.{member}('/tmp/inert', bytes); Deno.remove('/tmp/tail')");
        let nonconstructible = analyze("deno-eval-js", &code);
        assert!(nonconstructible.draft().calls().is_empty(), "{member}");
        assert!(nonconstructible.draft().complete(), "{member}");
    }

    for code in [
        "new Bun.spawn(['true']); Bun.write('/tmp/tail', 'text')",
        "new Bun.spawnSync(['true']); Bun.write('/tmp/tail', 'text')",
        "new Bun.file('/tmp/inert'); Bun.write('/tmp/tail', 'text')",
        "new Bun.write('/tmp/inert', 'text'); Bun.write('/tmp/tail', 'text')",
    ] {
        let nonconstructible = analyze("bun-js", code);
        assert!(nonconstructible.draft().calls().is_empty(), "{code}");
        assert!(
            nonconstructible.report().nested_executions().is_empty(),
            "{code}"
        );
        assert!(nonconstructible.draft().complete(), "{code}");
    }

    let bun_shell_constructor = analyze("bun-js", "new $(parts); Bun.spawn(['tail'])");
    assert!(bun_shell_constructor.draft().calls().is_empty());
    assert!(
        bun_shell_constructor
            .report()
            .nested_executions()
            .is_empty()
    );
    assert!(!bun_shell_constructor.draft().complete());
}

#[test]
fn deno_unowned_and_invalid_shapes_do_not_invent_effects() {
    // Run profiles stay unowned until routing carries effective Deno permission
    // grants; permission-unknown source must not fabricate capabilities.
    for profile in ["deno-run-js", "deno-checked-eval-js", "javascript"] {
        let analysis = analyze(
            profile,
            "Deno.remove('/tmp/a'); require('fs').rmSync('/tmp/b')",
        );
        assert!(analysis.draft().calls().is_empty(), "{profile}");
        assert!(!analysis.draft().complete(), "{profile}");
    }

    let invalid_write = analyze("deno-eval-js", "Deno.writeFile('/tmp/a', 'text')");
    assert!(invalid_write.draft().calls().is_empty());
    assert!(invalid_write.report().nested_executions().is_empty());
    assert!(invalid_write.draft().complete());

    for code in [
        "Deno.removeSync('/tmp/a', null); Deno.remove('/tmp/tail')",
        "Deno.writeFileSync('/tmp/a', 'text'); Deno.remove('/tmp/tail')",
        "Deno.writeTextFileSync('/tmp/a', 'text', {signal:false}); Deno.remove('/tmp/tail')",
    ] {
        let analysis = analyze("deno-eval-js", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.draft().complete(), "{code}");
    }

    let rejected_promise = analyze(
        "deno-eval-js",
        "Deno.writeFile('/tmp/a', 'text'); Deno.remove('/tmp/tail')",
    );
    assert_eq!(rejected_promise.draft().calls().len(), 1);
    assert_eq!(
        callable(&rejected_promise.draft().calls()[0]),
        "Deno.remove"
    );

    let awaited_rejection = analyze(
        "deno-eval-js",
        "await Deno.writeFile('/tmp/a', 'text'); Deno.remove('/tmp/tail')",
    );
    assert!(awaited_rejection.draft().calls().is_empty());
    assert!(awaited_rejection.draft().complete());

    let caught_rejection = analyze(
        "deno-eval-js",
        "try { await Deno.writeFile('/tmp/a', 'text') } catch { Deno.remove('/tmp/caught') }",
    );
    assert_eq!(caught_rejection.draft().calls().len(), 1);
    assert_eq!(
        callable(&caught_rejection.draft().calls()[0]),
        "Deno.remove"
    );
    assert!(caught_rejection.draft().complete());

    let bound_rejection = analyze(
        "deno-eval-js",
        "const p = Deno.writeFile('/tmp/a', 'text');\
         Deno.remove('/tmp/before'); await p; Deno.remove('/tmp/after')",
    );
    assert_eq!(bound_rejection.draft().calls().len(), 1);
    assert_eq!(callable(&bound_rejection.draft().calls()[0]), "Deno.remove");
    assert_eq!(
        bound_rejection.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/before")
    );

    let promise_truthiness = analyze(
        "deno-eval-js",
        "if (Deno.remove('/tmp/a')) Deno.remove('/tmp/b')",
    );
    assert_eq!(promise_truthiness.draft().calls().len(), 2);
    assert!(promise_truthiness.draft().complete());

    let reference_identity = analyze(
        "deno-eval-js",
        "const p = Deno.writeFile('/tmp/a', 'text');\
         if (p === p) Deno.remove('/tmp/tail')",
    );
    assert_eq!(reference_identity.draft().calls().len(), 1);
    assert!(!reference_identity.draft().complete());

    let partial_effects = analyze(
        "deno-eval-js",
        "Deno.remove('/tmp/remove', options);\
         Deno.mkdir('/tmp/mkdir', options);\
         Deno.readFile('/tmp/read', options);\
         Deno.writeFile('/tmp/write', bytes, options);\
         Deno.writeTextFile('/tmp/text', text, options)",
    );
    assert_eq!(partial_effects.draft().calls().len(), 5);
    assert_eq!(
        partial_effects
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        [
            "Deno.remove",
            "Deno.mkdir",
            "Deno.readFile",
            "Deno.writeFile",
            "Deno.writeTextFile",
        ]
    );
    assert!(partial_effects.draft().calls()[0].filesystems()[0].recursive());
    assert!(partial_effects.draft().calls()[1].filesystems()[0].recursive());
    assert!(!partial_effects.draft().complete());

    for code in [
        "await Deno.mkdir('/tmp/bad', {mode:-1}); Deno.remove('/tmp/tail')",
        "await Deno.writeTextFile('/tmp/bad', 'text', {mode:4294967296}); Deno.remove('/tmp/tail')",
        "await Deno.readFile('/tmp/bad', {signal:true}); Deno.remove('/tmp/tail')",
        "await Deno.writeTextFile('/tmp/bad', 'text', {signal:{}}); Deno.remove('/tmp/tail')",
        "Deno.mkdirSync('/tmp/bad', {mode:-1}); Deno.remove('/tmp/tail')",
        "Deno.writeTextFileSync('/tmp/bad', 'text', {mode:4294967296}); Deno.remove('/tmp/tail')",
    ] {
        let invalid_option = analyze("deno-eval-js", code);
        assert!(invalid_option.draft().calls().is_empty(), "{code}");
        assert!(invalid_option.draft().complete(), "{code}");
    }

    let valid_option_boundaries = analyze(
        "deno-eval-js",
        "await Deno.mkdir('/tmp/max-mode', {mode:4294967295});\
         await Deno.writeTextFile('/tmp/false-signal', 'text', {mode:0, signal:false})",
    );
    assert_eq!(valid_option_boundaries.draft().calls().len(), 2);
    assert!(valid_option_boundaries.draft().complete());

    for code in [
        "const p = Deno.remove('/tmp/first'); p(); Deno.remove('/tmp/tail')",
        "const p = Deno.remove('/tmp/first'); new p(); Deno.remove('/tmp/tail')",
    ] {
        let non_callable_promise = analyze("deno-eval-js", code);
        assert_eq!(non_callable_promise.draft().calls().len(), 1, "{code}");
        assert_eq!(
            non_callable_promise.draft().calls()[0].filesystems()[0].requested(),
            Some("/tmp/first"),
            "{code}"
        );
        assert!(non_callable_promise.draft().complete(), "{code}");
    }

    let unawaited_async_helper = analyze(
        "deno-eval-js",
        "async function fail() { await Deno.writeFile('/tmp/a', 'text') }\
         fail(); Deno.remove('/tmp/tail')",
    );
    assert_eq!(unawaited_async_helper.draft().calls().len(), 1);
    assert_eq!(
        unawaited_async_helper.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/tail")
    );

    let awaited_async_helper = analyze(
        "deno-eval-js",
        "async function fail() { await Deno.writeFile('/tmp/a', 'text') }\
         await fail(); Deno.remove('/tmp/tail')",
    );
    assert!(awaited_async_helper.draft().calls().is_empty());
    assert!(awaited_async_helper.draft().complete());

    let extracted = analyze(
        "deno-eval-js",
        "const remove = Deno.remove; remove('/tmp/a')",
    );
    assert_eq!(extracted.draft().calls().len(), 1);
    assert_eq!(callable(&extracted.draft().calls()[0]), "Deno.remove");
    assert!(extracted.draft().complete());

    let runtime_shapes = analyze(
        "deno-eval-js",
        "Deno.remove('/tmp/a', {recursive:'yes', future:true}, 'ignored');\
         Deno.mkdir('/tmp/b', {future:true}, 'ignored');\
         Deno.readFile('/tmp/c', {signal:false}, 'ignored');\
         Deno.writeTextFile('/tmp/d', 42, {append:true, signal:0}, 'ignored');\
         Deno.writeTextFileSync('/tmp/e', null);\
         Deno.writeTextFileSync('/tmp/f')",
    );
    assert_eq!(runtime_shapes.draft().calls().len(), 6);
    assert!(runtime_shapes.draft().calls()[0].filesystems()[0].recursive());
    assert!(runtime_shapes.draft().complete());

    let destructured = analyze(
        "deno-eval-js",
        "const {remove, Command} = Deno; remove('/tmp/a'); new Command('true').spawn()",
    );
    assert_eq!(destructured.draft().calls().len(), 2);
    assert_eq!(destructured.report().nested_executions().len(), 1);
    assert!(destructured.draft().complete());
}

#[test]
fn eval_preserves_abrupt_control_and_barriers_dynamic_results() {
    let caught = analyze(
        "deno-eval-js",
        "try { eval('throw 1') } catch { Deno.remove('/tmp/caught') }",
    );
    assert_eq!(caught.draft().calls().len(), 1);
    assert_eq!(callable(&caught.draft().calls()[0]), "Deno.remove");
    assert!(caught.draft().complete());

    let uncaught = analyze("deno-eval-js", "eval('throw 1'); Deno.remove('/tmp/tail')");
    assert!(uncaught.draft().calls().is_empty());
    assert!(uncaught.draft().complete());

    for code in [
        "function stop(){while(true){}} try{stop()}catch{Deno.remove('/caught')} Deno.remove('/tail')",
        "try{eval('while(true){}')}finally{Deno.remove('/finally')} Deno.remove('/tail')",
    ] {
        let divergent = analyze("deno-eval-js", code);
        assert!(divergent.draft().calls().is_empty(), "{code}");
        assert!(divergent.draft().complete(), "{code}");
    }

    let known_non_strings = analyze(
        "deno-eval-js",
        "const p=Deno.remove('/first'); eval(p); eval(Deno); Deno.remove('/tail')",
    );
    assert_eq!(known_non_strings.draft().calls().len(), 2);
    assert!(known_non_strings.draft().complete());

    for code in [
        "const f=eval(\"()=>Deno.remove('/hidden')\"); f(); Deno.remove('/tail')",
        "eval('Deno.remove')('/hidden'); Deno.remove('/tail')",
        "eval(\"function f(){Deno.remove('/hidden')}\"); f(); Deno.remove('/tail')",
    ] {
        let dynamic_result = analyze("deno-eval-js", code);
        assert!(dynamic_result.draft().calls().is_empty(), "{code}");
        assert!(!dynamic_result.draft().complete(), "{code}");
    }

    let eval_command = analyze(
        "deno-eval-js",
        "new Deno.Command(eval(\"'rm'\"), {args:['-rf','/']}).spawn()",
    );
    assert_eq!(eval_command.draft().calls().len(), 1);
    assert_eq!(
        callable(&eval_command.draft().calls()[0]),
        "Deno.Command.spawn"
    );
    assert!(eval_command.report().nested_executions().is_empty());
    assert!(!eval_command.draft().complete());

    let eval_options = analyze(
        "deno-eval-js",
        "Deno.remove('/tmp/a', eval('({recursive:true})'))",
    );
    assert_eq!(eval_options.draft().calls().len(), 1);
    assert!(eval_options.draft().calls()[0].filesystems()[0].recursive());
    assert!(!eval_options.draft().complete());

    let eval_identity = analyze(
        "deno-eval-js",
        "if (eval(\"'x'\") === 'x') Deno.remove('/tmp/maybe')",
    );
    assert_eq!(eval_identity.draft().calls().len(), 1);
    assert!(!eval_identity.draft().complete());
}

#[test]
fn dynamic_function_construction_is_inert_and_exact_bodies_run_on_invocation() {
    let inert = analyze(
        "deno-eval-js",
        "const f=Function(\"Deno.remove('/hidden')\"); Deno.remove('/tail')",
    );
    assert_eq!(inert.draft().calls().len(), 1);
    assert_eq!(
        inert.draft().calls()[0].filesystems()[0].requested(),
        Some("/tail")
    );
    assert!(inert.draft().complete());

    let invoked = analyze(
        "deno-eval-js",
        "Function(\"Deno.remove('/first')\")(); new Function(\"Deno.remove('/second')\")()",
    );
    assert_eq!(invoked.draft().calls().len(), 2);
    assert_eq!(
        invoked
            .draft()
            .calls()
            .iter()
            .map(|call| call.filesystems()[0].requested().unwrap())
            .collect::<Vec<_>>(),
        ["/first", "/second"]
    );
    assert!(invoked.draft().complete());

    let argument_order = analyze(
        "deno-eval-js",
        "Function(\"Deno.remove('/body')\")(Deno.remove('/argument'))",
    );
    assert_eq!(
        argument_order
            .draft()
            .calls()
            .iter()
            .map(|call| call.filesystems()[0].requested().unwrap())
            .collect::<Vec<_>>(),
        ["/argument", "/body"]
    );

    let global_only = analyze(
        "deno-eval-js",
        "{ const Deno={}; Function(\"Deno.remove('/global')\")() }",
    );
    assert_eq!(global_only.draft().calls().len(), 1);
    assert_eq!(
        global_only.draft().calls()[0].filesystems()[0].requested(),
        Some("/global")
    );
    assert!(global_only.draft().complete());

    let primitive_body = analyze(
        "deno-eval-js",
        "Function(1)(); Function(true)(); Deno.remove('/tail')",
    );
    assert_eq!(primitive_body.draft().calls().len(), 1);
    assert!(primitive_body.draft().complete());

    let valid_parameters = analyze(
        "deno-eval-js",
        "Function('value', 'return value'); Deno.remove('/tail')",
    );
    assert_eq!(valid_parameters.draft().calls().len(), 1);
    assert!(valid_parameters.draft().complete());
}

#[test]
fn dynamic_function_errors_divergence_and_opaque_values_do_not_leak() {
    for code in [
        "try { Function('}') } catch { Deno.remove('/caught') }",
        "try { Function('a-', 'return 1') } catch { Deno.remove('/caught') }",
        "try { Function('throw 1')() } catch { Deno.remove('/caught') }",
    ] {
        let caught = analyze("deno-eval-js", code);
        assert_eq!(caught.draft().calls().len(), 1, "{code}");
        assert_eq!(callable(&caught.draft().calls()[0]), "Deno.remove");
        assert!(caught.draft().complete(), "{code}");
    }

    for code in [
        "Function('while(true){}')(); Deno.remove('/tail')",
        "try { Function('while(true){}')() } finally { Deno.remove('/finally') } Deno.remove('/tail')",
    ] {
        let divergent = analyze("deno-eval-js", code);
        assert!(divergent.draft().calls().is_empty(), "{code}");
        assert!(divergent.draft().complete(), "{code}");
    }

    for code in [
        "const f=Function({}); f(); Deno.remove('/tail')",
        "Function('Deno = {}')(); Deno.remove('/tail')",
        "const f=Function(\"return function(){Deno.remove('/hidden')}\")(); f(); Deno.remove('/tail')",
    ] {
        let barrier = analyze("deno-eval-js", code);
        assert!(barrier.draft().calls().is_empty(), "{code}");
        assert!(!barrier.draft().complete(), "{code}");
    }
}

#[test]
fn deno_runtime_options_validate_before_and_after_process_creation() {
    for options in [
        "{clearEnv:'yes'}",
        "{uid:-1}",
        "{gid:4294967296}",
        "{cwd:false}",
        "{env:null}",
        "{env:{A:1}}",
        "{env:['ok', false]}",
    ] {
        let code = format!("new Deno.Command('true', {options}).spawn(); Deno.remove('/tmp/tail')");
        let analysis = analyze("deno-eval-js", &code);
        assert!(analysis.draft().calls().is_empty(), "{options}");
        assert!(
            analysis.report().nested_executions().is_empty(),
            "{options}"
        );
        assert!(analysis.draft().complete(), "{options}");
    }

    let caught_preflight = analyze(
        "deno-eval-js",
        "try { new Deno.Command('true', {uid:-1}).spawn() }\
         catch { Deno.remove('/tmp/caught') }",
    );
    assert_eq!(caught_preflight.draft().calls().len(), 1);
    assert_eq!(
        callable(&caught_preflight.draft().calls()[0]),
        "Deno.remove"
    );

    for consumer in ["spawn", "output"] {
        let code = format!(
            "new Deno.Command('true', {{signal:1}}).{consumer}(); Deno.remove('/tmp/tail')"
        );
        let analysis = analyze("deno-eval-js", &code);
        assert_eq!(analysis.draft().calls().len(), 1, "{consumer}");
        assert_eq!(
            callable(&analysis.draft().calls()[0]),
            format!("Deno.Command.{consumer}"),
            "{consumer}"
        );
        assert_eq!(analysis.report().nested_executions().len(), 1, "{consumer}");
        assert!(analysis.draft().complete(), "{consumer}");
    }

    let synchronous_signal_is_ignored = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {signal:1}).outputSync(); Deno.remove('/tmp/tail')",
    );
    assert_eq!(synchronous_signal_is_ignored.draft().calls().len(), 2);
    assert_eq!(
        synchronous_signal_is_ignored
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["Deno.Command.outputSync", "Deno.remove"]
    );
    assert_eq!(
        synchronous_signal_is_ignored
            .report()
            .nested_executions()
            .len(),
        1
    );

    let platform_ignored_options = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {windowsRawArguments:1}).spawn();\
         Deno.remove('/tmp/tail')",
    );
    assert_eq!(platform_ignored_options.draft().calls().len(), 2);
    assert_eq!(
        platform_ignored_options.report().nested_executions().len(),
        1
    );
    assert!(platform_ignored_options.draft().complete());

    let uncertain_fd = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {stdout:3}).spawn(); Deno.remove('/tmp/tail')",
    );
    assert_eq!(uncertain_fd.draft().calls().len(), 2);
    assert!(uncertain_fd.report().nested_executions().is_empty());
    assert!(!uncertain_fd.draft().complete());

    let unrelated_getter = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {get telemetry(){throw 1}}).spawn();\
         new Deno.Command('true', {get telemetry(){throw 1}}).outputSync()",
    );
    assert_eq!(unrelated_getter.draft().calls().len(), 2);
    assert_eq!(
        unrelated_getter
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["Deno.Command.spawn", "Deno.Command.outputSync"]
    );
    assert_eq!(unrelated_getter.report().nested_executions().len(), 1);
    assert!(!unrelated_getter.draft().complete());

    let caught_after_spawn = analyze(
        "deno-eval-js",
        "try { new Deno.Command('true', {signal:1}).spawn() }\
         catch { Deno.remove('/tmp/caught') }",
    );
    assert_eq!(caught_after_spawn.draft().calls().len(), 2);
    assert_eq!(
        callable(&caught_after_spawn.draft().calls()[0]),
        "Deno.Command.spawn"
    );
    assert_eq!(
        callable(&caught_after_spawn.draft().calls()[1]),
        "Deno.remove"
    );
    assert_eq!(caught_after_spawn.report().nested_executions().len(), 1);

    let null_signal = analyze(
        "deno-eval-js",
        "new Deno.Command('true', {signal:null}).spawn();\
         new Deno.Command('true', {signal:null}).output();\
         Deno.remove('/tmp/tail')",
    );
    assert_eq!(null_signal.draft().calls().len(), 2);
    assert_eq!(
        null_signal
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["Deno.Command.spawn", "Deno.Command.output"]
    );
    assert_eq!(null_signal.report().nested_executions().len(), 2);
}

#[test]
fn runtime_option_prototypes_widen_only_consumed_values() {
    for code in [
        "Number.prototype.args=['-rf','/']; new Deno.Command('rm', 1).spawn()",
        "Function.prototype.cwd='/'; new Deno.Command('rm', function () {}).spawn()",
        "Array.prototype.env={}; new Deno.Command('rm', []).spawn()",
        "Object.setPrototypeOf({}, {args:['-rf','/']}); new Deno.Command('rm', {}).spawn()",
        "new Deno.Command('rm', {__proto__:{args:['-rf','/']}}).spawn()",
        "Object.prototype.cmd=['rm','-rf','/']; Bun.spawn({})",
    ] {
        let profile = if code.contains("Bun") {
            "bun-js"
        } else {
            "deno-eval-js"
        };
        let analysis = analyze(profile, code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }

    let inherited_recursive = analyze(
        "deno-eval-js",
        "Deno.remove('/tmp/a', {__proto__:{recursive:true}})",
    );
    assert_eq!(inherited_recursive.draft().calls().len(), 1);
    assert!(inherited_recursive.draft().calls()[0].filesystems()[0].recursive());
    assert!(!inherited_recursive.draft().complete());

    let omitted_options = analyze(
        "deno-eval-js",
        "Object.prototype.args=['not-used'];\
         new Deno.Command('true').spawn();\
         new Deno.Command('true', undefined).output()",
    );
    assert_eq!(omitted_options.draft().calls().len(), 2);
    assert_eq!(omitted_options.report().nested_executions().len(), 2);

    let unrelated_names = analyze(
        "deno-eval-js",
        "function localFn() {}\
         localFn.prototype.x=1;\
         const obj={}; obj.prototypeSafe=1; obj['not.prototype']=1;\
         new Deno.Command('true').spawn()",
    );
    assert_eq!(unrelated_names.draft().calls().len(), 1);
    assert_eq!(unrelated_names.report().nested_executions().len(), 1);

    for code in [
        "Object.prototype.recursive=true; Deno.mkdirSync('/tmp/a', {mode:-1}); Deno.remove('/tmp/tail')",
        "Object.prototype.createPath=true; Bun.write('/tmp/a', 'text', {mode:512}); Bun.spawn(['tail'])",
    ] {
        let profile = if code.contains("Bun") {
            "bun-js"
        } else {
            "deno-eval-js"
        };
        let analysis = analyze(profile, code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
    }
}

#[test]
fn bun_owns_node_builtins_and_exact_runtime_primitives() {
    let analysis = analyze(
        "bun-typescript",
        "import {rm} from 'node:fs/promises';\
         await rm('/tmp/old', {recursive:true});\
         Bun.spawn(['rm', '-rf', '/tmp/a']);\
         Bun.spawnSync({cmd:['mkdir', '/tmp/b']});\
         await Bun.file('/tmp/input').text();\
         await Bun.file('/tmp/delete').delete();\
         await Bun.write('/tmp/output', Bun.file('/tmp/source'))",
    );
    assert_eq!(
        analysis
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        [
            "fs.promises.rm",
            "Bun.spawn",
            "Bun.spawnSync",
            "Bun.file.text",
            "Bun.file.delete",
            "Bun.write",
        ]
    );
    assert_eq!(analysis.report().nested_executions().len(), 2);
    assert_eq!(
        analysis.draft().calls()[3].filesystems()[0].operation(),
        FilesystemOperation::Read
    );
    assert_eq!(
        analysis.draft().calls()[4].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert_eq!(analysis.draft().calls()[5].filesystems().len(), 2);
}

#[test]
fn bun_lazy_values_shell_and_invalid_shapes_resist_false_positives() {
    let lazy = analyze("bun-js", "const file = Bun.file('/tmp/input')");
    assert!(lazy.draft().calls().is_empty());
    assert!(lazy.draft().complete());

    let shell = analyze("bun-tsx", "$`rm -rf /tmp/cache`");
    assert!(shell.draft().calls().is_empty());
    assert!(shell.report().nested_executions().is_empty());
    assert!(!shell.draft().complete());

    for code in ["Bun.spawn('rm')", "Bun.file()", "Bun.write(-1, 'text')"] {
        let analysis = analyze("bun-js", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(analysis.draft().complete(), "{code}");
    }

    let string_command = analyze("bun-js", "Bun.spawnSync({cmd:'rm'})");
    assert_eq!(string_command.draft().calls().len(), 1);
    assert!(matches!(
        string_command.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv.iter().map(String::as_str).eq(["r", "m"])
    ));
    assert!(string_command.draft().complete());

    for options in [
        "{env:false}",
        "{stdin:true}",
        "{stderr:true}",
        "{timeout:'x'}",
    ] {
        let code = format!("Bun.spawn(['true'], {options}); Bun.write('/tmp/tail', 'text')");
        let invalid_options = analyze("bun-js", &code);
        assert!(invalid_options.draft().calls().is_empty(), "{options}");
        assert!(
            invalid_options.report().nested_executions().is_empty(),
            "{options}"
        );
        assert!(invalid_options.draft().complete(), "{options}");
    }

    let uncertain_context = analyze(
        "bun-js",
        "Bun.spawn(['true'], {cwd:false}); Bun.write('/tmp/tail', 'text')",
    );
    assert_eq!(uncertain_context.draft().calls().len(), 2);
    assert!(uncertain_context.report().nested_executions().is_empty());
    assert!(!uncertain_context.draft().complete());

    let scalar_options = analyze(
        "bun-js",
        "Bun.spawn(['true'], false); Bun.spawnSync(['true'], 0)",
    );
    assert_eq!(scalar_options.draft().calls().len(), 2);
    assert_eq!(scalar_options.report().nested_executions().len(), 2);
    assert!(scalar_options.draft().complete());

    let extracted = analyze(
        "bun-js",
        "const spawn = Bun.spawn; spawn(['rm', '-rf', '/'])",
    );
    assert_eq!(extracted.draft().calls().len(), 1);
    assert_eq!(callable(&extracted.draft().calls()[0]), "Bun.spawn");
    assert!(matches!(
        extracted.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv.iter().map(String::as_str).eq(["rm", "-rf", "/"])
    ));
    assert!(extracted.draft().complete());

    let accepted_options = analyze(
        "bun-js",
        "Bun.spawn(['rm', '-rf', '/tmp/a'], {cwd:'/'});\
         Bun.spawnSync({cmd:['mkdir', '/tmp/b'], cwd:'/'});\
         Bun.file('/tmp/input', {type:'text/plain'}, 'ignored').text('ignored');\
         Bun.write('/tmp/output', 'text', {mode:420}, 'ignored')",
    );
    assert_eq!(
        accepted_options
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["Bun.spawn", "Bun.spawnSync", "Bun.file.text", "Bun.write"]
    );
    assert_eq!(accepted_options.report().nested_executions().len(), 2);
    assert!(
        accepted_options
            .report()
            .nested_executions()
            .iter()
            .all(|execution| matches!(
                execution,
                NestedExecution::Command {
                    cwd: NestedExecutionCwd::Path(cwd),
                    ..
                } if cwd == "/"
            ))
    );
    assert!(accepted_options.draft().complete());

    for member in ["spawn", "spawnSync"] {
        let analysis = analyze(
            "bun-js",
            &format!(
                "Bun.{member}(['printf', 'default']);\
                 Bun.{member}(['printf', 'pipe'], {{stdout:'pipe'}});\
                 Bun.{member}(['printf', 'inherit'], {{stdout:'inherit'}});\
                 Bun.{member}(['printf', 'null'], {{stdout:null}});\
                 Bun.{member}(['printf', 'fd1'], {{stdout:1}});\
                 Bun.{member}(['printf', 'fd2'], {{stdout:2}})"
            ),
        );
        assert_eq!(analysis.draft().calls().len(), 6, "{member}");
        assert_eq!(
            analysis
                .report()
                .nested_executions()
                .iter()
                .map(|execution| match execution {
                    NestedExecution::Command {
                        stdout_inherited, ..
                    } => *stdout_inherited,
                    NestedExecution::Shell { .. } => panic!("Bun spawn emits argv"),
                })
                .collect::<Vec<_>>(),
            [false, false, true, false, true, false],
            "{member}"
        );
        assert!(analysis.draft().complete(), "{member}");
    }

    for stdout in ["true", "false", "-1", "0", "'invalid'"] {
        let code =
            format!("Bun.spawn(['true'], {{stdout:{stdout}}}); Bun.write('/tmp/tail', 'text')");
        let invalid_stdout = analyze("bun-js", &code);
        assert!(invalid_stdout.draft().calls().is_empty(), "{stdout}");
        assert!(
            invalid_stdout.report().nested_executions().is_empty(),
            "{stdout}"
        );
        assert!(invalid_stdout.draft().complete(), "{stdout}");
    }

    let unknown_fd = analyze(
        "bun-js",
        "Bun.spawn(['true'], {stdout:3}); Bun.write('/tmp/tail', 'text')",
    );
    assert_eq!(unknown_fd.draft().calls().len(), 2);
    assert!(unknown_fd.report().nested_executions().is_empty());
    assert!(!unknown_fd.draft().complete());

    for mode in ["-1", "512", "4294967295"] {
        let code = format!("Bun.write('/tmp/bad', 'text', {{mode:{mode}}}); Bun.spawn(['tail'])");
        let invalid_mode = analyze("bun-js", &code);
        assert!(invalid_mode.draft().calls().is_empty(), "{mode}");
        assert!(
            invalid_mode.report().nested_executions().is_empty(),
            "{mode}"
        );
        assert!(invalid_mode.draft().complete(), "{mode}");
    }

    let valid_modes = analyze(
        "bun-js",
        "Bun.write('/tmp/zero', 'text', {mode:0});\
         Bun.write('/tmp/max', 'text', {mode:511})",
    );
    assert_eq!(valid_modes.draft().calls().len(), 2);
    assert!(valid_modes.draft().complete());

    let dynamic_commands = analyze(
        "bun-js",
        "Bun.spawn(command); Bun.spawnSync({cmd: command})",
    );
    assert_eq!(dynamic_commands.draft().calls().len(), 2);
    assert!(dynamic_commands.report().nested_executions().is_empty());
    assert!(!dynamic_commands.draft().complete());

    let runtime_coercions = analyze(
        "bun-js",
        "const {spawn, file, write} = Bun;\
         spawn(['printf', 7], null);\
         spawn({cmd:['printf', true], telemetry:'ignored'});\
         file('/tmp/input', {type:1}).bytes('ignored');\
         write(7, false, null);\
         write('/tmp/object', {}, [])",
    );
    assert_eq!(runtime_coercions.draft().calls().len(), 5);
    assert_eq!(runtime_coercions.report().nested_executions().len(), 2);
    assert!(!runtime_coercions.draft().complete());

    for code in [
        "Bun.file(); Bun.spawn(['rm', '-rf', '/'])",
        "void Bun.file(); Bun.spawn(['rm', '-rf', '/'])",
        "Bun.file() && Bun.spawn(['rm', '-rf', '/'])",
        "[Bun.file(), Bun.spawn(['rm', '-rf', '/'])]",
        "({first:Bun.file(), second:Bun.spawn(['rm', '-rf', '/'])})",
        "Bun.spawn('rm'); Bun.write('/tmp/tail', 'text')",
        "Bun.write(-1, 'text'); Bun.spawn(['rm'])",
        "const {value = Bun.file()} = {}; Bun.spawn(['rm'])",
        "const [value = Bun.file()] = []; Bun.spawn(['rm'])",
        "const [value] = {}; Bun.spawn(['rm'])",
        "const {[Bun.file()]: value} = {}; Bun.spawn(['rm'])",
        "obj[Bun.file()] = Bun.spawn(['rm'])",
        "obj[Bun.file()] = 1; Bun.spawn(['rm'])",
        "const text = Bun.file('/tmp/a').text; text(); Bun.spawn(['rm'])",
    ] {
        let synchronous_throw = analyze("bun-js", code);
        assert!(synchronous_throw.draft().calls().is_empty(), "{code}");
        assert!(
            synchronous_throw.report().nested_executions().is_empty(),
            "{code}"
        );
        assert!(synchronous_throw.draft().complete(), "{code}");
    }

    let invalid_fd = analyze("bun-js", "Bun.file(-1).text(); Bun.spawn(['rm'])");
    assert!(invalid_fd.draft().calls().is_empty());
    assert!(invalid_fd.report().nested_executions().is_empty());
    assert!(invalid_fd.draft().complete());

    let caught = analyze("bun-js", "try { Bun.file() } catch { Bun.spawn(['true']) }");
    assert_eq!(caught.draft().calls().len(), 1);
    assert_eq!(caught.report().nested_executions().len(), 1);
    assert!(caught.draft().complete());

    let promise_spread = analyze(
        "bun-js",
        "const p = Bun.write('/tmp/a', 'text'); Bun.spawn(...p); Bun.spawn(['tail'])",
    );
    assert_eq!(promise_spread.draft().calls().len(), 1);
    assert_eq!(callable(&promise_spread.draft().calls()[0]), "Bun.write");
    assert!(promise_spread.draft().complete());

    let promise_truthiness = analyze(
        "bun-js",
        "if (Bun.write('/tmp/a', 'text')) {} else { Bun.file('/tmp/false').delete() }",
    );
    assert_eq!(promise_truthiness.draft().calls().len(), 1);
    assert_eq!(
        callable(&promise_truthiness.draft().calls()[0]),
        "Bun.write"
    );
    assert!(promise_truthiness.draft().complete());

    let partial_writes = analyze(
        "bun-js",
        "Bun.write('/tmp/source-unknown', source);\
         Bun.write('/tmp/options-unknown', 'text', options)",
    );
    assert_eq!(partial_writes.draft().calls().len(), 2);
    assert!(
        partial_writes
            .draft()
            .calls()
            .iter()
            .all(|call| callable(call) == "Bun.write")
    );
    assert!(!partial_writes.draft().complete());

    let object_like_writes = analyze(
        "bun-js",
        "async function rejected() { throw 1 }\
         const promise = Bun.write('/tmp/seed', 'text');\
         Bun.write('/tmp/function-source', () => {});\
         Bun.write('/tmp/bun-source', Bun);\
         Bun.write('/tmp/promise-source', promise);\
         Bun.write('/tmp/rejected-source', rejected());\
         Bun.write('/tmp/function-options', 'text', () => {});\
         Bun.write('/tmp/bun-options', 'text', Bun);\
         Bun.write('/tmp/promise-options', 'text', promise)",
    );
    assert_eq!(object_like_writes.draft().calls().len(), 8);
    assert!(
        object_like_writes
            .draft()
            .calls()
            .iter()
            .all(|call| callable(call) == "Bun.write")
    );
    assert!(!object_like_writes.draft().complete());
}

#[test]
fn openclaw_owns_only_direct_intrinsic_tool_calls() {
    for profile in ["openclaw-javascript", "openclaw-typescript"] {
        let analysis = analyze(
            profile,
            "await tools.call('read_file', {path:'/tmp/a'}); return tools.callValue('status')",
        );
        assert!(analysis.draft().calls().is_empty(), "{profile}");
        assert!(
            analysis.report().nested_executions().is_empty(),
            "{profile}"
        );
        assert!(!analysis.draft().complete(), "{profile}");
    }

    for code in ["tools.call('')", "tools.call(7)", "tools.call()"] {
        let analysis = analyze("openclaw-javascript", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(analysis.draft().complete(), "{code}");
    }

    let unawaited_rejection = analyze(
        "openclaw-javascript",
        "tools.call(7); tools.call('read_file')",
    );
    assert!(!unawaited_rejection.draft().complete());

    let awaited_rejection = analyze(
        "openclaw-javascript",
        "await tools.call(7); tools.call('read_file')",
    );
    assert!(awaited_rejection.draft().complete());

    let caught_rejection = analyze(
        "openclaw-javascript",
        "try { await tools.call(7) } catch { tools.call('read_file') }",
    );
    assert!(!caught_rejection.draft().complete());

    for code in [
        "const p = tools.call(7); p(); tools.call('read_file')",
        "const p = tools.call(7); new p(); tools.call('read_file')",
    ] {
        assert!(
            analyze("openclaw-javascript", code).draft().complete(),
            "{code}"
        );
    }

    let unawaited_async_helper = analyze(
        "openclaw-javascript",
        "async function fail() { await tools.call(7) } fail(); tools.call('read_file')",
    );
    assert!(!unawaited_async_helper.draft().complete());

    let awaited_async_helper = analyze(
        "openclaw-javascript",
        "async function fail() { await tools.call(7) } await fail(); tools.call('read_file')",
    );
    assert!(awaited_async_helper.draft().complete());

    for code in [
        "tools.call('read_file', 'schema validation happens downstream')",
        "tools.call('read_file', {}, 3)",
    ] {
        let analysis = analyze("openclaw-javascript", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }
}

#[test]
fn openclaw_aliases_are_owned_while_shadowed_dormant_and_node_calls_are_inert() {
    let dormant = analyze(
        "openclaw-javascript",
        "function later() { tools.call('read_file', {path:'/tmp/a'}) } return 1",
    );
    assert!(dormant.draft().calls().is_empty());
    assert!(dormant.report().nested_executions().is_empty());
    assert!(dormant.draft().complete());

    for code in [
        "const call = tools.call; call('read_file', {path:'/tmp/a'})",
        "const {callValue} = tools; callValue('read_file', {path:'/tmp/a'})",
    ] {
        let analysis = analyze("openclaw-javascript", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }

    for code in [
        "const call = tools.call; call('')",
        "const {callValue} = tools; callValue('')",
    ] {
        assert!(analyze("openclaw-javascript", code).draft().complete());
    }

    for code in [
        "const tools = {}; tools.call('read_file', {path:'/tmp/a'})",
        "require('fs').rmSync('/tmp/a')",
    ] {
        let analysis = analyze("openclaw-javascript", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }
}
