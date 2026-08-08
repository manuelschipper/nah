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
    analyze_program("python3", code)
}

fn analyze_program<'a>(program: &'a str, code: &'a str) -> LanguageAnalysis {
    analyze_program_platform(program, code, Platform::Linux)
}

fn analyze_program_platform<'a>(
    program: &'a str,
    code: &'a str,
    platform: Platform,
) -> LanguageAnalysis {
    analyze_with_language_effects(
        InlineInput {
            program,
            code,
            home: "/home/dev",
            platform,
        },
        ProtectionInput {
            critical_paths: &[],
            ambient_variables: &[],
        },
    )
}

#[test]
fn javascript_direct_file_call_uses_canonical_effects_only() {
    let analysis = analyze_program(
        "node",
        "require('node:fs').rmSync('/tmp/cache', {recursive:true})",
    );
    assert!(analysis.report().findings().is_empty());
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind(), LanguageCallKind::DirectFile);
    assert_eq!(callable(&calls[0]), "fs.rmSync");
    assert_eq!(
        native(&calls[0]),
        (
            &json!({
                "v": 2,
                "language": "javascript",
                "callable": "fs.rmSync",
                "positional": [
                    {"kind": "string", "value": "/tmp/cache"},
                    {
                        "kind": "object",
                        "properties": [{
                            "name": "recursive",
                            "value": {"kind": "bool", "value": true},
                        }],
                    },
                ],
                "keywords": [],
            }),
            true,
        )
    );
    assert_eq!(calls[0].filesystems().len(), 1);
    assert_eq!(
        calls[0].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert!(calls[0].filesystems()[0].recursive());
    assert!(analysis.draft().complete());
}

#[test]
fn javascript_node_parity_preserves_source_and_destination_semantics() {
    let analysis = analyze_program(
        "node",
        "const fs=require('fs');\nfs.copyFileSync('/protected/source', '/safe/backup');\nfs.copyFileSync('/safe/source', '/protected/destination');\nfs.createWriteStream('/protected/stream');\nfs.openSync('/protected/open', 'w');\nfs.linkSync('/protected/source', '/safe/link');\nfs.chmodSync('/protected/mode', 0);",
    );
    let calls = analysis.draft().calls();
    assert_eq!(
        calls.iter().map(callable).collect::<Vec<_>>(),
        [
            "fs.copyFileSync",
            "fs.copyFileSync",
            "fs.createWriteStream",
            "fs.openSync",
            "fs.linkSync",
            "fs.chmodSync",
        ]
    );
    assert_eq!(
        calls[0]
            .filesystems()
            .iter()
            .map(|filesystem| (filesystem.requested(), filesystem.operation()))
            .collect::<Vec<_>>(),
        [
            (Some("/protected/source"), FilesystemOperation::Read),
            (Some("/safe/backup"), FilesystemOperation::Write),
        ]
    );
    assert_eq!(
        calls[1]
            .filesystems()
            .iter()
            .map(|filesystem| (filesystem.requested(), filesystem.operation()))
            .collect::<Vec<_>>(),
        [
            (Some("/safe/source"), FilesystemOperation::Read),
            (Some("/protected/destination"), FilesystemOperation::Write),
        ]
    );
    assert_eq!(
        calls[4].filesystems()[1].identity_path(),
        Some("/protected/source")
    );
    assert!(calls[4].filesystems()[1].identity_observed());
    assert!(!calls[5].filesystems()[0].content_access());
    assert!(analysis.draft().complete());
}

#[test]
fn javascript_child_calls_keep_canonical_evidence_and_shell_provenance() {
    let analysis = analyze_program(
        "node",
        "const cp=require('node:child_process'); cp.execSync('printf ok'); cp.spawn('nah', ['nap'])",
    );
    assert_eq!(
        analysis
            .draft()
            .calls()
            .iter()
            .map(|call| (call.kind(), callable(call)))
            .collect::<Vec<_>>(),
        [
            (LanguageCallKind::EvaluatedShell, "child_process.execSync"),
            (LanguageCallKind::LocalUtility, "child_process.spawn"),
        ]
    );
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }, NestedExecution::Command { argv, .. }]
            if program == "sh"
                && code == "printf ok"
                && argv.iter().map(String::as_str).eq(["nah", "nap"])
    ));
    assert!(!analysis.draft().complete());
}

#[test]
fn javascript_child_process_documented_overloads_keep_the_primary_call() {
    for (source, expected, kind, complete) in [
        (
            "cp.exec('printf ok', {encoding:'utf8'}, () => {})",
            "child_process.exec",
            LanguageCallKind::EvaluatedShell,
            false,
        ),
        (
            "cp.execSync('printf ok', {shell:'/bin/bash'})",
            "child_process.execSync",
            LanguageCallKind::EvaluatedShell,
            true,
        ),
        (
            "cp.spawn('rm', {stdio:'ignore'})",
            "child_process.spawn",
            LanguageCallKind::LocalUtility,
            true,
        ),
        (
            "cp.spawn('rm', ['-rf', '/'], {shell:false})",
            "child_process.spawn",
            LanguageCallKind::LocalUtility,
            true,
        ),
        (
            "cp.spawnSync('rm', {})",
            "child_process.spawnSync",
            LanguageCallKind::LocalUtility,
            true,
        ),
        (
            "cp.execFile('rm', ['-rf', '/'], {}, () => {})",
            "child_process.execFile",
            LanguageCallKind::LocalUtility,
            false,
        ),
        (
            "cp.execFile('rm', {stdio:'ignore'}, () => {})",
            "child_process.execFile",
            LanguageCallKind::LocalUtility,
            false,
        ),
        (
            "cp.execFileSync('rm', ['-rf', '/'], {})",
            "child_process.execFileSync",
            LanguageCallKind::LocalUtility,
            true,
        ),
    ] {
        let code = format!("const cp=require('child_process'); {source}");
        let analysis = analyze_program("node", &code);
        assert!(
            matches!(
                analysis.draft().calls(),
                [call] if callable(call) == expected && call.kind() == kind
            ),
            "{source}"
        );
        assert_eq!(analysis.draft().complete(), complete, "{source}");
    }
}

#[test]
fn javascript_child_shell_modes_preserve_dialect_and_context_uncertainty() {
    let bash = analyze_program(
        "node",
        "require('child_process').spawn('rm', ['-rf', '/'], {shell:'/bin/bash'})",
    );
    assert_eq!(
        bash.draft().calls()[0].kind(),
        LanguageCallKind::EvaluatedShell
    );
    assert!(matches!(
        bash.report().nested_executions(),
        [NestedExecution::Shell { program, code, .. }]
            if program == "bash" && code == "rm -rf /"
    ));
    assert!(bash.draft().complete());

    for source in [
        "require('child_process').execSync('[[ -e / ]] && rm -rf /')",
        "require('child_process').spawn('rm', ['-rf', '/'], {shell:true})",
        "require('child_process').execFileSync('rm', ['-rf', '/'], {shell:'/bin/echo'})",
    ] {
        let analysis = analyze_program("node", source);
        assert!(
            matches!(
                analysis.draft().calls(),
                [call] if call.kind() == LanguageCallKind::EvaluatedShell
            ),
            "{source}"
        );
        assert!(
            matches!(
                analysis.report().nested_executions(),
                [NestedExecution::Shell { program, .. }] if program != "bash"
            ),
            "{source}"
        );
        assert!(!analysis.draft().complete(), "{source}");
    }

    let argv = analyze_program(
        "node",
        "require('child_process').spawn('rm', ['-rf', '/'], {shell:false})",
    );
    assert!(matches!(
        argv.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv.iter().map(String::as_str).eq(["rm", "-rf", "/"])
    ));
    assert!(argv.draft().complete());

    let cwd = analyze_program(
        "node",
        "require('child_process').spawn('rm', ['-rf', '.'], {cwd:'/'})",
    );
    assert_eq!(
        cwd.draft().calls()[0].kind(),
        LanguageCallKind::LocalUtility
    );
    assert!(cwd.report().nested_executions().is_empty());
    assert!(!cwd.draft().complete());

    let windows = analyze_program_platform(
        "node",
        "require('child_process').execSync('rm -rf /', {shell:'/bin/bash'})",
        Platform::Windows,
    );
    assert!(matches!(
        windows.report().nested_executions(),
        [NestedExecution::Shell { program, .. }] if program == "/bin/bash"
    ));
    assert!(!windows.draft().complete());
}

#[test]
fn javascript_child_callbacks_are_conditional_and_invalid_shapes_stay_inert() {
    let callback = analyze_program(
        "node",
        "const cp=require('child_process'), fs=require('fs'); cp.execFile('true', () => fs.rmSync('/', {recursive:true}))",
    );
    assert_eq!(
        callback
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["child_process.execFile", "fs.rmSync"]
    );
    assert_eq!(callback.draft().calls()[1].execution_dominators(), &[0]);
    assert!(!callback.draft().complete());

    for source in [
        "require('child_process').spawn('rm', '-rf', '/')",
        "require('child_process').execSync('printf ok', () => {})",
        "require('child_process').execFile('rm', [], {}, 'not a callback')",
    ] {
        let analysis = analyze_program("node", source);
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(analysis.draft().complete(), "{source}");
    }

    let accessor = analyze_program(
        "node",
        "require('child_process').spawn('rm', [], {get shell(){return false}})",
    );
    assert!(accessor.draft().calls().is_empty());
    assert!(!accessor.draft().complete());
}

#[test]
fn javascript_rebinding_and_unowned_hosts_never_invent_node_effects() {
    let rebound = analyze_program(
        "node",
        "const fs=require('fs'); fs.copyFileSync=safe; fs.copyFileSync('/safe', '/protected')",
    );
    assert!(rebound.draft().calls().is_empty());
    assert!(!rebound.draft().complete());

    for (program, code) in [
        (
            "javascript",
            "await tools.exec({command:'rm -rf /'}); require('fs').rmSync('/')",
        ),
        ("typescript", "await tools.remove('/protected')"),
        ("bun", "Bun.spawn(['rm', '-rf', '/'])"),
        ("deno-run-typescript", "await Deno.remove('/protected')"),
    ] {
        let analysis = analyze_program(program, code);
        assert!(analysis.draft().calls().is_empty(), "{program}");
        assert!(!analysis.draft().complete(), "{program}");
    }
}

#[test]
fn typescript_wrappers_are_transparent_for_owned_tsx_calls() {
    let analysis = analyze_program(
        "tsx",
        "interface Job { path: string }\ntype Target = string\nconst fs: typeof import('node:fs') = require('node:fs') as typeof import('node:fs')\nasync function clean(path: string) { await fs.rmSync(path!, {recursive:true}) }\nawait clean('/tmp/cache')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(callable(&calls[0]), "fs.rmSync");
    assert_eq!(calls[0].filesystems()[0].requested(), Some("/tmp/cache"));
    assert_eq!(native(&calls[0]).0["language"], "tsx");
    assert!(analysis.draft().complete());
}

#[test]
fn javascript_profiles_preserve_source_context_and_deno_ambiguity() {
    let direct = analyze_program("javascript", "return; tools.remove('/unreachable')");
    assert!(direct.draft().calls().is_empty());
    assert!(direct.draft().complete());
    assert!(direct.report().refusals().is_empty());

    let node = analyze_program("node", "return; require('fs').rmSync('/unreachable')");
    assert!(node.draft().calls().is_empty());
    assert!(!node.draft().complete());

    let deno = analyze_program("deno", "const element = <Widget value={1} />");
    assert!(deno.draft().calls().is_empty());
    assert!(!deno.draft().complete());

    let typed = analyze_program(
        "deno-run-typescript",
        "type Job = { value: number }; const value: number = 1",
    );
    assert!(typed.draft().calls().is_empty());
    assert!(typed.draft().complete());
}

#[test]
fn malformed_javascript_is_partial_without_legacy_scanner_refusals() {
    for code in [
        "const target = ; require('fs').rmSync('/tmp/cache')",
        "require('fs').rmSync('/tmp/cache')]",
        "const target = 'unterminated",
    ] {
        let analysis = analyze_program("node", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
        assert!(analysis.report().refusals().is_empty(), "{code}");
    }
}

#[test]
fn javascript_unknown_branches_and_cwd_changes_remain_explicit() {
    let analysis = analyze_program(
        "node",
        "const fs=require('fs'); if (condition) { fs.rmSync('/tmp/a') ; fs.rmSync('/tmp/b') } plugin(); fs.rmSync('relative')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].conditional_depth(), 1);
    assert_eq!(calls[1].execution_dominators(), &[0]);
    assert_eq!(calls[2].filesystems()[0].requested(), None);
    assert!(!analysis.draft().complete());
}

#[test]
fn javascript_functions_resolve_lexical_instead_of_caller_scopes() {
    let safe_closure = analyze_program(
        "node",
        "const fs={rmSync:(path, options)=>{}}; function clean(){fs.rmSync('/', {recursive:true})} {const fs=require('fs'); clean()}",
    );
    assert!(safe_closure.draft().calls().is_empty());
    assert!(safe_closure.draft().complete());

    let owned_closure = analyze_program(
        "node",
        "const fs=require('fs'); function clean(){fs.rmSync('/', {recursive:true})} {const fs={rmSync:(path, options)=>{}}; clean()}",
    );
    assert_eq!(owned_closure.draft().calls().len(), 1);
    assert_eq!(
        owned_closure.draft().calls()[0].filesystems()[0].requested(),
        Some("/")
    );
    assert!(owned_closure.draft().complete());
}

#[test]
fn javascript_accessor_execution_is_an_explicit_barrier() {
    for code in [
        "const fs=require('fs'); const value={get path(){fs.rmSync('/', {recursive:true}); return '/'}}; value.path",
        "const fs=require('fs'), value={}; Object.defineProperty(value, 'path', {get(){fs.rmSync('/', {recursive:true})}}); value.path",
        "const fs=require('fs'); const value={get path(){fs.rmSync('/', {recursive:true}); return '/'}}; const {path}=value",
        "const fs=require('fs'); const value={get path(){fs.rmSync('/', {recursive:true}); return '/'}}; const copy={...value}",
    ] {
        let analysis = analyze_program("node", code);
        assert!(!analysis.draft().complete(), "{code}");
    }
}

#[test]
fn javascript_fs_overloads_preserve_effect_and_return_semantics() {
    let analysis = analyze_program(
        "node",
        "const fs=require('fs'); fs.mkdirSync('/tmp/numeric-mode', 0o700); fs.mkdirSync('/tmp/string-mode', '0700'); fs.createWriteStream('/tmp/string', 'utf8'); if(fs.createWriteStream('/tmp/stream')) fs.rmSync('/', {recursive:true})",
    );
    assert_eq!(
        analysis
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        [
            "fs.mkdirSync",
            "fs.mkdirSync",
            "fs.createWriteStream",
            "fs.createWriteStream",
            "fs.rmSync",
        ]
    );
    assert_eq!(
        analysis.draft().calls()[4].filesystems()[0].requested(),
        Some("/")
    );
    assert!(analysis.draft().complete());

    let descriptor = analyze_program(
        "node",
        "const fs=require('fs'); fs.createWriteStream('/protected', {fd:1})",
    );
    assert_eq!(descriptor.draft().calls().len(), 1);
    assert_eq!(
        descriptor.draft().calls()[0].filesystems()[0].requested(),
        None
    );
    assert!(!descriptor.draft().complete());

    let numeric_flags = analyze_program("node", "require('fs').openSync('/tmp/x', 0)");
    assert!(numeric_flags.draft().calls().is_empty());
    assert!(!numeric_flags.draft().complete());

    let invalid = analyze_program("node", "require('fs').mkdirSync('/tmp/x', false)");
    assert!(invalid.draft().calls().is_empty());
    assert!(invalid.draft().complete());
}

#[test]
fn javascript_fs_callbacks_and_option_accessors_are_explicitly_partial() {
    let callback = analyze_program(
        "node",
        "const fs=require('fs'); fs.writeFile('/tmp/x', 'data', () => fs.rmSync('/', {recursive:true}))",
    );
    assert_eq!(callback.draft().calls().len(), 2);
    assert_eq!(callable(&callback.draft().calls()[0]), "fs.writeFile");
    assert_eq!(callable(&callback.draft().calls()[1]), "fs.rmSync");
    assert_eq!(callback.draft().calls()[1].execution_dominators(), &[0]);
    assert!(!callback.draft().complete());

    for code in [
        "require('fs').rm('/tmp/x', {get recursive(){return true}}, () => {})",
        "require('fs').writeFile('/tmp/x', 'data', {get flag(){return 'w'}}, () => {})",
        "require('fs').createWriteStream('/tmp/x', {get fd(){return 1}})",
        "require('fs/promises').mkdir('/tmp/x', {get mode(){return '0700'}})",
    ] {
        let analysis = analyze_program("node", code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }
}

#[test]
fn javascript_fs_promises_imports_are_owned_and_rebinding_is_shared() {
    let analysis = analyze_program(
        "node",
        "const direct=require('node:fs/promises'); const via=require('fs').promises; direct.rm('/tmp/a', {recursive:true}); via.unlink('/tmp/b')",
    );
    assert_eq!(
        analysis
            .draft()
            .calls()
            .iter()
            .map(callable)
            .collect::<Vec<_>>(),
        ["fs.promises.rm", "fs.promises.unlink"]
    );
    assert!(analysis.draft().complete());

    let imported = analyze_program(
        "node",
        "import {writeFile} from 'node:fs/promises'; writeFile('/tmp/x', 'data')",
    );
    assert_eq!(
        callable(&imported.draft().calls()[0]),
        "fs.promises.writeFile"
    );
    assert!(imported.draft().complete());

    let rebound = analyze_program(
        "node",
        "const direct=require('fs/promises'); const alias=direct; alias.rm=safe; direct.rm('/', {recursive:true})",
    );
    assert!(rebound.draft().calls().is_empty());
    assert!(!rebound.draft().complete());
}

#[test]
fn javascript_eval_merges_canonical_calls_without_legacy_findings() {
    let analysis = analyze_program("node", "eval(\"require('fs').rmSync('/tmp/cache')\")");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "fs.rmSync");
    assert!(analysis.report().findings().is_empty());
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

    let analysis = analyze("import os\nos.rename('src', '/dst', src_dir_fd=3)");
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[1].requested(),
        Some("/dst")
    );
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[1].identity_path(),
        None
    );
    assert!(!analysis.draft().complete());

    let analysis = analyze("import os\nos.link('src', '/dst', src_dir_fd=3)");
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[1].requested(),
        Some("/dst")
    );
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[1].identity_path(),
        None
    );
    assert!(!analysis.draft().complete());

    let analysis = analyze("import os\nos.link('/src', '/dst', src_dir_fd=3)");
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[1].identity_path(),
        Some("/src")
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
fn subprocess_context_options_keep_known_calls_partial_without_nested_execution() {
    for (code, expected, kind) in [
        (
            "import subprocess\nsubprocess.run(['rm','-rf','.'], cwd='/')",
            "subprocess.run",
            LanguageCallKind::LocalUtility,
        ),
        (
            "import subprocess\nsubprocess.Popen(['rm','-rf','.'], cwd='/')",
            "subprocess.popen",
            LanguageCallKind::LocalUtility,
        ),
        (
            "import subprocess\nsubprocess.run(['rm','-rf','.'], env={'PATH':'/bin'})",
            "subprocess.run",
            LanguageCallKind::LocalUtility,
        ),
        (
            "import subprocess\nsubprocess.run(['rm','-rf','.'], executable='/bin/rm')",
            "subprocess.run",
            LanguageCallKind::LocalUtility,
        ),
        (
            "import subprocess\nsubprocess.run(command)",
            "subprocess.run",
            LanguageCallKind::LocalUtility,
        ),
        (
            "import subprocess\nsubprocess.run('rm -rf .', shell=True, cwd='/')",
            "subprocess.run",
            LanguageCallKind::EvaluatedShell,
        ),
    ] {
        let analysis = analyze(code);
        assert!(
            matches!(analysis.draft().calls(), [call] if callable(call) == expected && call.kind() == kind),
            "{code}"
        );
        assert!(analysis.report().nested_executions().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }

    let exact = analyze("import subprocess\nsubprocess.run(['rm','-rf','/'])");
    assert!(matches!(
        exact.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv.iter().map(String::as_str).eq(["rm", "-rf", "/"])
    ));
    assert!(exact.draft().complete());
}

#[test]
fn definitely_invalid_known_call_shapes_stop_following_effects() {
    for code in [
        "import os\nos.remove()\nos.remove('/tmp/tail')",
        "import os\nos.remove('/tmp/x', 'extra', *args)\nos.remove('/tmp/tail')",
        "import os\nos.removedirs(path='/tmp/x')\nos.remove('/tmp/tail')",
        "import shutil\nshutil.copyfile('/tmp/a', '/tmp/b', copy_function=None)\nshutil.rmtree('/tmp/tail')",
        "import shutil\nshutil.copytree('/tmp/a', '/tmp/b', follow_symlinks=False)\nshutil.rmtree('/tmp/tail')",
        "import requests\nrequests.delete('https://example.test', None)\nrequests.get('https://tail.test')",
        "import requests\nrequests.get('https://example.test', bogus=True)\nrequests.get('https://tail.test')",
        "import httpx\nhttpx.get('https://example.test', None)\nhttpx.get('https://tail.test')",
        "import httpx\nhttpx.get('https://example.test', bogus=True)\nhttpx.get('https://tail.test')",
        "import urllib.request\nurllib.request.urlopen('https://example.test', None, 1, None)\nurllib.request.urlopen('https://tail.test')",
        "import urllib.request\nurllib.request.urlretrieve('https://example.test', None, None, None, None)\nurllib.request.urlopen('https://tail.test')",
        "import os\np=os.getenv('HOME', None, 'extra')\nos.remove('/tmp/tail')",
        "import os\ngetattr(os, 'remove', None, None)('/tmp/x')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').with_name('y', 'extra').unlink()\nos.remove('/tmp/tail')",
        "import os\nos.open('/tmp/x')\nos.remove('/tmp/tail')",
        "import os\nos.open('/tmp/x', os.O_RDONLY, 0o644, None)\nos.remove('/tmp/tail')",
        "import os\nos.rename('/tmp/a')\nos.remove('/tmp/tail')",
        "import os\nos.rename('/tmp/a', '/tmp/b', None)\nos.remove('/tmp/tail')",
        "import os\nos.replace(source='/tmp/a', destination='/tmp/b')\nos.remove('/tmp/tail')",
        "import os\nos.link('/tmp/a', '/tmp/b', False)\nos.remove('/tmp/tail')",
        "import os\nos.symlink('/tmp/a', '/tmp/b', False, None)\nos.remove('/tmp/tail')",
        "import os\nos.mkdir('/tmp/x', 0o755, None)\nos.remove('/tmp/tail')",
        "import os\nos.chown('/tmp/x', 0, 0, None)\nos.remove('/tmp/tail')",
        "import os\nos.lchown('/tmp/x', 0, 0, dir_fd=None)\nos.remove('/tmp/tail')",
        "import shutil\nshutil.rmtree('/tmp/x', dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.remove('/tmp/x', dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.mkdir('/tmp/x', mode='bad')\nos.remove('/tmp/tail')",
        "import os\nos.mkdir('/tmp/x', dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.truncate('/tmp/x', 'bad')\nos.remove('/tmp/tail')",
        "import os\nos.chmod('/tmp/x', 'bad')\nos.remove('/tmp/tail')",
        "import os\nos.chmod('/tmp/x', 0o600, dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.chown('/tmp/x', 'bad', 0)\nos.remove('/tmp/tail')",
        "import os\nos.chown('/tmp/x', 0, 'bad')\nos.remove('/tmp/tail')",
        "import os\nos.chown('/tmp/x', 0, 0, dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.lchown('/tmp/x', 'bad', 0)\nos.remove('/tmp/tail')",
        "import os\nos.rename('/tmp/a', '/tmp/b', src_dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.replace('/tmp/a', '/tmp/b', dst_dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.link('/tmp/a', '/tmp/b', src_dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.symlink('/tmp/a', '/tmp/b', dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nos.open('/tmp/x', 'bad')\nos.remove('/tmp/tail')",
        "import os\nos.open('/tmp/x', os.O_CREAT, 'bad')\nos.remove('/tmp/tail')",
        "import os\nos.open('/tmp/x', os.O_RDONLY, dir_fd='bad')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').mkdir(mode='bad')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').chmod('bad')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').lchmod('bad')\nos.remove('/tmp/tail')",
        "import shutil\nshutil.move('/tmp/a', '/tmp/b', copy, None)\nshutil.rmtree('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/a').rename('/tmp/b', None)\nos.remove('/tmp/tail')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    let analysis = analyze("import os\nos.remove(*args)\nos.remove('/tmp/tail')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
    assert!(!analysis.draft().complete());

    let analysis = analyze("import os\nos.rename(*args)\nos.remove('/tmp/tail')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
    assert!(!analysis.draft().complete());

    for (program, code) in [
        (
            "python3.7",
            "import shutil\nshutil.copytree('/tmp/a', '/tmp/b', dirs_exist_ok=True)\nshutil.rmtree('/tmp/tail')",
        ),
        (
            "python3.13",
            "import urllib.request\nurllib.request.urlopen('https://example.test', cafile=None)\nurllib.request.urlopen('https://tail.test')",
        ),
        (
            "python3.2",
            "import urllib.request\nurllib.request.urlopen('https://example.test', cadefault=False)\nurllib.request.urlopen('https://tail.test')",
        ),
        (
            "python3.3",
            "import urllib.request\nurllib.request.urlopen('https://example.test', context=None)\nurllib.request.urlopen('https://tail.test')",
        ),
        (
            "python3.2",
            "import shutil\nshutil.copyfile('/tmp/a', '/tmp/b', follow_symlinks=False)\nshutil.rmtree('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.remove(path='/tmp/x')\nos.remove('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.remove('/tmp/x', dir_fd=None)\nos.remove('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.rename(src='/tmp/a', dst='/tmp/b')\nos.remove('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.link('/tmp/a', '/tmp/b', follow_symlinks=False)\nos.remove('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.open(path='/tmp/x', flags=0)\nos.remove('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.replace('/tmp/a', '/tmp/b')\nos.remove('/tmp/tail')",
        ),
        (
            "python3.2",
            "import os\nos.symlink('/tmp/a', '/tmp/b', False)\nos.remove('/tmp/tail')",
        ),
        (
            "python3.4",
            "import shutil\nshutil.move('/tmp/a', '/tmp/b', copy)\nshutil.rmtree('/tmp/tail')",
        ),
        (
            "python3.4",
            "import os\nos.lchown(path='/tmp/x', uid=0, gid=0)\nos.remove('/tmp/tail')",
        ),
        (
            "python3.11",
            "import shutil\nshutil.rmtree('/tmp/a', onexc=handler)\nshutil.rmtree('/tmp/tail')",
        ),
    ] {
        assert!(
            analyze_program(program, code).draft().calls().is_empty(),
            "{program}: {code}"
        );
    }
}

#[test]
fn unknown_index_arguments_keep_possible_effects_partial() {
    for code in [
        "import os\nos.remove('/tmp/x', dir_fd=fd)\nos.remove('/tmp/tail')",
        "import os\nos.chmod('/tmp/x', mode)\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').chmod(mode)\nos.remove('/tmp/tail')",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 2, "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }

    let analysis = analyze(
        "import os\ntry:\n    os.chmod('/tmp/x', 'bad')\nexcept:\n    os.remove('/tmp/caught')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/caught")
    );
}

#[test]
fn definitely_invalid_pre_effect_arguments_stop_before_tail() {
    for code in [
        "import os\nfrom pathlib import Path\nos.popen(Path('printf unsafe'))\nos.remove('/tmp/tail')",
        "import os\nos.popen('printf unsafe', mode='x')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nos.popen('printf unsafe', mode=Path('r'))\nos.remove('/tmp/tail')",
        "import os\nos.popen('printf unsafe', buffering='bad')\nos.remove('/tmp/tail')",
        "import os\nos.popen('printf unsafe', buffering=0)\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nopen('/tmp/head', Path('w'))\nos.remove('/tmp/tail')",
        "import os\nopen('/tmp/head', 'w', buffering='bad')\nos.remove('/tmp/tail')",
        "import io, os\nfrom pathlib import Path\nio.FileIO('/tmp/head', Path('w'))\nos.remove('/tmp/tail')",
        "import io, os\nio.FileIO('/tmp/head', 'q')\nos.remove('/tmp/tail')",
        "import os\nos.execv('/bin/rm', 'rm')\nos.remove('/tmp/tail')",
        "import os\nos.execv('/bin/rm', [])\nos.remove('/tmp/tail')",
        "import os\nos.execv('/bin/rm', ['rm', 1])\nos.remove('/tmp/tail')",
        "import os\nos.execle('/bin/rm', 'rm', 1)\nos.remove('/tmp/tail')",
        "import os\nos.execv('', ['rm'])\nos.remove('/tmp/tail')",
        "import os\nos.execv('/bin/rm')\nos.remove('/tmp/tail')",
        "import os, subprocess\nsubprocess.run([], shell=False)\nos.remove('/tmp/tail')",
        "import os, subprocess\nsubprocess.run([''])\nos.remove('/tmp/tail')",
        "import os, subprocess\nsubprocess.run(b'')\nos.remove('/tmp/tail')",
        "import os, subprocess\nsubprocess.run(['printf'], bufsize='bad')\nos.remove('/tmp/tail')",
        "import os\nos.symlink([], '/tmp/link')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/head').write_text(b'bad')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/head').write_bytes('bad')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/link').symlink_to([])\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\ncompile(Path('pass'), '<x>', 'exec')\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\ncompile('pass', '<x>', Path('exec'))\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\ngetattr(os, Path('remove'))\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\n__import__(Path('os'))\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nos.getenv(Path('HOME'))\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').with_name(Path('y'))\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').with_name('.nah/trust.json').unlink()\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/').with_name('x').unlink()\nos.remove('/tmp/tail')",
        "import os\nopen(-1, 'w')\nos.remove('/tmp/tail')",
        "import io, os\nio.FileIO(-1, 'w')\nos.remove('/tmp/tail')",
        "import os\n__import__('os', level=None)\nos.remove('/tmp/tail')",
        "import os\n__import__('os', level=-1)\nos.remove('/tmp/tail')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    let analysis =
        analyze("import os\nopen('/tmp/head', 'w', buffering=0)\nos.remove('/tmp/tail')");
    assert!(matches!(analysis.draft().calls(), [call] if callable(call) == "builtins.open"));

    let analysis =
        analyze("import os\nopen('/tmp/head', 'wb', buffering=0)\nos.remove('/tmp/tail')");
    assert_eq!(analysis.draft().calls().len(), 2);
}

#[test]
fn reviewed_pre_effect_argument_values_remain_valid() {
    for (code, expected) in [
        (
            "import os\nos.popen('printf safe', mode='r', buffering=1)",
            "os.popen",
        ),
        ("open('/tmp/head', 'w', buffering=1)", "builtins.open"),
        ("import io\nio.FileIO('/tmp/head', 'wb')", "io.fileio"),
        (
            "import os\nos.execv('/bin/rm', ['rm', '-f', '/tmp/head'])",
            "os.execv",
        ),
        (
            "import os\nos.execle('/bin/rm', 'rm', '-f', '/tmp/head', {})",
            "os.execle",
        ),
        (
            "import os\nos.execvpe('/bin/rm', ['rm', '-f', '/tmp/head'], os.environ)",
            "os.execvpe",
        ),
        (
            "import os\nos.execle('/bin/rm', 'rm', '-f', '/tmp/head', os.environ)",
            "os.execle",
        ),
        (
            "import subprocess\nsubprocess.run([], shell=True)",
            "subprocess.run",
        ),
        (
            "import subprocess\nsubprocess.run(['printf'], bufsize=None)",
            "subprocess.run",
        ),
        (
            "import os\nos.symlink('/tmp/source', '/tmp/link')",
            "os.symlink",
        ),
        (
            "from pathlib import Path\nPath('/tmp/head').write_text('safe')",
            "pathlib.path.write_text",
        ),
        (
            "from pathlib import Path\nPath('/tmp/head').write_bytes(b'safe')",
            "pathlib.path.write_bytes",
        ),
        (
            "from pathlib import Path\nPath('/tmp/link').symlink_to(Path('/tmp/source'))",
            "pathlib.path.symlink_to",
        ),
        (
            "import os\nfrom pathlib import Path\ncompile('pass', Path('<x>'), 'exec')\nos.remove('/tmp/tail')",
            "os.remove",
        ),
        ("import os\ngetattr(os, 'remove')('/tmp/head')", "os.remove"),
        ("__import__('os').remove('/tmp/head')", "os.remove"),
        (
            "import os\nos.remove(os.getenv('HOME') + '/tmp')",
            "os.remove",
        ),
        (
            "from pathlib import Path\nPath('/tmp/x').with_name('y').unlink()",
            "pathlib.path.unlink",
        ),
        (
            "import base64\nopen('/tmp/head', base64.b64decode(b'dw==').decode())",
            "builtins.open",
        ),
        (
            "import base64, os\nos.popen('printf safe', base64.b64decode(b'cg==').decode())",
            "os.popen",
        ),
        ("__import__('os', level=0).remove('/tmp/head')", "os.remove"),
    ] {
        let analysis = analyze(code);
        assert!(
            matches!(analysis.draft().calls(), [call] if callable(call) == expected),
            "{code}"
        );
    }
}

#[test]
fn unresolved_pre_effect_arguments_keep_possible_paths_partial() {
    for (code, expected) in [
        ("import os\nos.popen(command, mode, buffering)", "os.popen"),
        (
            "open('/tmp/head', 'w', buffering=buffering)",
            "builtins.open",
        ),
        ("open('/tmp/head', mode)", "builtins.open"),
        ("import io\nio.FileIO('/tmp/head', mode)", "io.fileio"),
        ("import os\nos.execv(program, argv)", "os.execv"),
        (
            "import subprocess\nsubprocess.run(argv, bufsize=bufsize)",
            "subprocess.run",
        ),
        ("import os\nos.symlink(source, '/tmp/link')", "os.symlink"),
        (
            "from pathlib import Path\nPath('/tmp/head').write_text(data)",
            "pathlib.path.write_text",
        ),
        (
            "from pathlib import Path\nPath('/tmp/link').symlink_to(target)",
            "pathlib.path.symlink_to",
        ),
    ] {
        let analysis = analyze(code);
        assert!(
            matches!(analysis.draft().calls(), [call] if callable(call) == expected),
            "{code}"
        );
        assert!(!analysis.draft().complete(), "{code}");
    }

    for code in [
        "import os\nfrom pathlib import Path\ncompile(source, '<x>', 'exec')\nos.remove('/tmp/tail')",
        "import os\ngetattr(os, name)\nos.remove('/tmp/tail')",
        "import os\n__import__(name)\nos.remove('/tmp/tail')",
        "import os\nos.getenv(key)\nos.remove('/tmp/tail')",
        "import os\nfrom pathlib import Path\nPath('/tmp/x').with_name(name)\nos.remove('/tmp/tail')",
    ] {
        let analysis = analyze(code);
        assert!(
            matches!(analysis.draft().calls(), [call] if callable(call) == "os.remove"),
            "{code}"
        );
        assert!(!analysis.draft().complete(), "{code}");
    }
}

#[test]
fn reviewed_keyword_and_positional_call_shapes_remain_valid() {
    for (code, expected) in [
        ("import os\nos.remove(path='/tmp/x')", "os.remove"),
        ("import os\nos.removedirs(name='/tmp/a/b')", "os.removedirs"),
        ("import os\nos.lchown('/tmp/x', 0, 0)", "os.lchown"),
        (
            "import shutil\nshutil.copyfile('/tmp/a', '/tmp/b', follow_symlinks=False)",
            "shutil.copyfile",
        ),
        (
            "import shutil\nshutil.copytree('/tmp/a', '/tmp/b', copy_function=copy, dirs_exist_ok=True)",
            "shutil.copytree",
        ),
        (
            "import requests\nrequests.post('https://example.test', None, None, timeout=1)",
            "requests.post",
        ),
        (
            "import httpx\nhttpx.get('https://example.test', timeout=1)",
            "httpx.get",
        ),
        (
            "import httpx\nhttpx.get('https://example.test', proxies=None, cert=None)",
            "httpx.get",
        ),
        (
            "import urllib.request\nurllib.request.urlopen('https://example.test', None, 1, context=None)",
            "urllib.request.urlopen",
        ),
        (
            "import os\nos.remove(os.getenv(key='HOME') + '/x')",
            "os.remove",
        ),
        (
            "import os\ngetattr(os, 'remove', None)('/tmp/x')",
            "os.remove",
        ),
        (
            "import os\ngetattr(os, 'remove', **{})('/tmp/x')",
            "os.remove",
        ),
        (
            "from pathlib import Path\nPath('/tmp/x').with_name(name='y').unlink()",
            "pathlib.path.unlink",
        ),
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(callable(&analysis.draft().calls()[0]), expected, "{code}");
    }

    for (program, code, expected) in [
        (
            "python3.8",
            "import shutil\nshutil.copytree('/tmp/a', '/tmp/b', dirs_exist_ok=True)",
            "shutil.copytree",
        ),
        (
            "python3.12",
            "import urllib.request\nurllib.request.urlopen('https://example.test', cafile=None)",
            "urllib.request.urlopen",
        ),
        (
            "python3.2",
            "import urllib.request\nurllib.request.urlopen('https://example.test', cafile=None)",
            "urllib.request.urlopen",
        ),
        (
            "python3.3",
            "import urllib.request\nurllib.request.urlopen('https://example.test', cadefault=False)",
            "urllib.request.urlopen",
        ),
        (
            "python3.4",
            "import urllib.request\nurllib.request.urlopen('https://example.test', context=None)",
            "urllib.request.urlopen",
        ),
        (
            "python3.3",
            "import shutil\nshutil.copyfile('/tmp/a', '/tmp/b', follow_symlinks=False)",
            "shutil.copyfile",
        ),
        (
            "python3.3",
            "import os\nos.remove(path='/tmp/x', dir_fd=None)",
            "os.remove",
        ),
        (
            "python3.3",
            "import os\nos.rename(src='/tmp/a', dst='/tmp/b', src_dir_fd=None, dst_dir_fd=None)",
            "os.rename",
        ),
        (
            "python3.3",
            "import os\nos.link(src='/tmp/a', dst='/tmp/b', follow_symlinks=False)",
            "os.link",
        ),
        (
            "python3.3",
            "import os\nos.open(path='/tmp/x', flags=0, dir_fd=None)",
            "os.open",
        ),
        (
            "python3.3",
            "import os\nos.symlink(src='/tmp/a', dst='/tmp/b', target_is_directory=False, dir_fd=None)",
            "os.symlink",
        ),
        (
            "python3.12",
            "import shutil\nshutil.rmtree('/tmp/a', onexc=handler)",
            "shutil.rmtree",
        ),
        (
            "python3.5",
            "import os\nos.lchown(path='/tmp/x', uid=0, gid=0)",
            "os.lchown",
        ),
    ] {
        let analysis = analyze_program(program, code);
        assert_eq!(analysis.draft().calls().len(), 1, "{program}: {code}");
        assert_eq!(
            callable(&analysis.draft().calls()[0]),
            expected,
            "{program}: {code}"
        );
    }

    let analysis = analyze_program_platform(
        "python3.2",
        "import os\nos.symlink(src='/tmp/a', dest='/tmp/b', target_is_directory=False)",
        Platform::Windows,
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.symlink");
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
fn rename_and_link_calls_preserve_identity() {
    let analysis = analyze(
        "import os\nfrom pathlib import Path\nos.rename('/a', '/b')\nos.link('/a', '/b')\nPath('/a').rename('/b')\nPath('/a').replace('/b')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 4);
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
    assert_eq!(calls[1].filesystems().len(), 2);
    assert_eq!(calls[1].filesystems()[0].requested(), Some("/a"));
    assert!(!calls[1].filesystems()[0].content_access());
    assert_eq!(calls[1].filesystems()[1].identity_path(), Some("/a"));
    assert!(calls[1].filesystems()[1].identity_requires_missing_target());
    assert!(calls[1].filesystems()[1].identity_observed());
    assert!(calls[1].filesystems()[1].identity_follows_final_symlink());
    assert_eq!(calls[2].filesystems()[1].identity_path(), Some("/a"));
    assert_eq!(calls[3].filesystems()[1].identity_path(), Some("/a"));
    assert!(analysis.draft().complete());
}

#[test]
fn namespace_and_no_follow_calls_preserve_final_symlinks() {
    let analysis = analyze(
        "import os\nfrom pathlib import Path\nos.rename('/a', '/b')\nos.symlink('/a', '/b')\nos.lchown('/a', 0, 0)\nos.chmod('/a', 0o600, follow_symlinks=False)\nos.chown('/a', 0, 0, follow_symlinks=False)\nPath('/a').lchmod(0o600)\nPath('/a').chmod(0o600, follow_symlinks=False)\nPath('/a').rename('/b')\nPath('/a').symlink_to('/b')",
    );
    let calls = analysis.draft().calls();
    assert_eq!(calls.len(), 9);
    for filesystem in [
        &calls[0].filesystems()[1],
        &calls[1].filesystems()[0],
        &calls[2].filesystems()[0],
        &calls[3].filesystems()[0],
        &calls[4].filesystems()[0],
        &calls[5].filesystems()[0],
        &calls[6].filesystems()[0],
        &calls[7].filesystems()[1],
        &calls[8].filesystems()[0],
    ] {
        assert!(!filesystem.follows_final_symlink());
    }

    let analysis = analyze("import os\nos.chmod('/a', 0o600)");
    assert!(analysis.draft().calls()[0].filesystems()[0].follows_final_symlink());

    let analysis = analyze("import os\nos.link('/a', '/b', follow_symlinks=False)");
    let filesystems = analysis.draft().calls()[0].filesystems();
    assert!(!filesystems[0].follows_final_symlink());
    assert!(!filesystems[1].identity_follows_final_symlink());
}

#[test]
fn ambiguous_directory_destinations_remain_partial() {
    for code in [
        "import shutil\nshutil.move('/tmp/other-tool', '/home/dev/.local/bin')",
        "import shutil\nshutil.copy('/tmp/other-tool', '/home/dev/.local/bin')",
        "import shutil\nshutil.copy2('/tmp/other-tool', '/home/dev/.local/bin')",
    ] {
        let analysis = analyze(code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }
}

#[test]
fn dir_fd_widens_only_relative_filesystem_paths() {
    for code in [
        "import os\nos.remove('relative', dir_fd=3)",
        "import os\nos.unlink('relative', dir_fd=3)",
        "import os\nos.rmdir('relative', dir_fd=3)",
        "import os\nos.mkdir('relative', dir_fd=3)",
        "import os\nos.rename('src', 'dst', src_dir_fd=3, dst_dir_fd=4)",
        "import os\nos.replace('src', 'dst', src_dir_fd=3, dst_dir_fd=4)",
        "import os\nos.link('src', 'dst', src_dir_fd=3, dst_dir_fd=4)",
        "import os\nos.symlink('src', 'dst', dir_fd=3)",
        "import os\nos.open('relative', os.O_RDONLY, dir_fd=3)",
        "import os\nos.chmod('relative', 0o600, dir_fd=3)",
        "import os\nos.chown('relative', 0, 0, dir_fd=3)",
        "import shutil\nshutil.rmtree('relative', dir_fd=3)",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert!(
            analysis.draft().calls()[0]
                .filesystems()
                .iter()
                .all(|filesystem| filesystem.requested().is_none()),
            "{code}"
        );
        assert!(!analysis.draft().complete(), "{code}");
    }

    for code in [
        "import os\nos.remove('/absolute', dir_fd=3)",
        "import os\nos.unlink('/absolute', dir_fd=3)",
        "import os\nos.rmdir('/absolute', dir_fd=3)",
        "import os\nos.mkdir('/absolute', dir_fd=3)",
        "import os\nos.rename('/src', '/dst', src_dir_fd=3, dst_dir_fd=4)",
        "import os\nos.replace('/src', '/dst', src_dir_fd=3, dst_dir_fd=4)",
        "import os\nos.link('/src', '/dst', src_dir_fd=3, dst_dir_fd=4)",
        "import os\nos.symlink('/src', '/dst', dir_fd=3)",
        "import os\nos.open('/absolute', os.O_RDONLY, dir_fd=3)",
        "import os\nos.chmod('/absolute', 0o600, dir_fd=3)",
        "import os\nos.chown('/absolute', 0, 0, dir_fd=3)",
        "import shutil\nshutil.rmtree('/absolute', dir_fd=3)",
    ] {
        let analysis = analyze(code);
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert!(
            analysis.draft().calls()[0]
                .filesystems()
                .iter()
                .all(|filesystem| filesystem.requested().is_some()),
            "{code}"
        );
        assert!(analysis.draft().complete(), "{code}");
    }

    let analysis = analyze("import os\nos.rename('src', 'dst', src_dir_fd=None, dst_dir_fd=None)");
    assert!(
        analysis.draft().calls()[0]
            .filesystems()
            .iter()
            .all(|filesystem| filesystem.requested().is_some())
    );
    assert!(analysis.draft().complete());
}

#[test]
fn os_open_append_uses_access_bits_for_write_effects() {
    let analysis = analyze("import os\nos.open('/tmp/x', os.O_RDONLY | os.O_APPEND)");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(analysis.draft().calls()[0].filesystems().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].operation(),
        FilesystemOperation::Read
    );

    let analysis = analyze("import os\nos.open('/tmp/x', os.O_WRONLY | os.O_APPEND)");
    assert_eq!(analysis.draft().calls()[0].filesystems().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].operation(),
        FilesystemOperation::Write
    );

    let analysis = analyze("import os\nos.open('/tmp/x', os.O_RDONLY | os.O_CREAT)");
    assert_eq!(analysis.draft().calls()[0].filesystems().len(), 2);
    assert_eq!(
        analysis.draft().calls()[0]
            .filesystems()
            .iter()
            .map(|filesystem| filesystem.operation())
            .collect::<Vec<_>>(),
        vec![FilesystemOperation::Read, FilesystemOperation::Write]
    );
}

#[test]
fn metadata_copies_protect_destination_descendants_only() {
    let analysis = analyze(
        "import shutil\nshutil.copymode('/src', '/dst')\nshutil.copystat('/src', '/dst')\nshutil.copyfile('/src', '/dst')",
    );
    assert_eq!(analysis.draft().calls().len(), 3);
    for call in &analysis.draft().calls()[..2] {
        assert!(!call.filesystems()[0].descendant_protection());
        assert!(call.filesystems()[1].descendant_protection());
    }
    assert!(!analysis.draft().calls()[2].filesystems()[1].descendant_protection());
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
fn class_body_abrupt_control_does_not_fall_through() {
    for code in [
        "import os\nclass Stop:\n    raise RuntimeError()\n    os.remove('/tmp/body')\nos.remove('/tmp/tail')",
        "import os\nclass Stop:\n    while True: pass\n    os.remove('/tmp/body')\nos.remove('/tmp/tail')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    let analysis = analyze(
        "import os\ntry:\n    class Stop:\n        raise RuntimeError()\nexcept:\n    os.remove('/tmp/caught')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/caught")
    );
}

#[test]
fn finally_preserves_abrupt_control_and_skips_divergent_paths() {
    let analysis = analyze(
        "import os\ndef finish():\n    try: return\n    finally: os.remove('/tmp/finally')\n    os.remove('/tmp/function-tail')\nfinish()",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/finally")
    );

    let analysis = analyze(
        "import os\ntry:\n    raise RuntimeError()\nfinally:\n    os.remove('/tmp/finally')\nos.remove('/tmp/tail')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/finally")
    );

    let analysis = analyze(
        "import os\ntry:\n    while True: pass\nfinally:\n    os.remove('/tmp/finally')\nos.remove('/tmp/tail')",
    );
    assert!(analysis.draft().calls().is_empty());
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
fn exact_dynamic_abrupt_control_does_not_fall_through() {
    for code in [
        "import os\nexec(\"raise RuntimeError()\")\nos.remove('/tmp/unreachable')",
        "import os\nexec(\"while True:\\n pass\")\nos.remove('/tmp/unreachable')",
        "import os\ndef stop(): raise RuntimeError()\neval(\"stop()\")\nos.remove('/tmp/unreachable')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    let analysis = analyze(
        "import os\ntry:\n    exec(\"raise RuntimeError()\")\nexcept:\n    os.remove('/tmp/caught')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/caught")
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
fn definitely_invalid_local_calls_stop_following_effects() {
    for code in [
        "import os\ndef f(required): pass\nf()\nos.remove('/tmp/tail')",
        "import os\ndef f(value): pass\nf(1, 2)\nos.remove('/tmp/tail')",
        "import os\ndef f(value): pass\nf(1, 2, *args)\nos.remove('/tmp/tail')",
        "import os\ndef f(value): pass\nf(other=1)\nos.remove('/tmp/tail')",
        "import os\ndef f(value): pass\nf(1, value=2)\nos.remove('/tmp/tail')",
    ] {
        assert!(analyze(code).draft().calls().is_empty(), "{code}");
    }

    let analysis = analyze("import os\ndef f(value): pass\nf(*args)\nos.remove('/tmp/tail')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.remove");
    assert!(!analysis.draft().complete());
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

    let analysis = analyze(
        "import os\ntry:\n    open('/tmp/x', 'zz')\nexcept ValueError:\n    pass\nos.system('rm -rf /')",
    );
    assert!(matches!(
        analysis.report().nested_executions(),
        [NestedExecution::Shell { code, .. }] if code == "rm -rf /"
    ));
    assert!(!analysis.draft().complete());

    let analysis =
        analyze("import os\nos.execl('/bin/true', 'true')\nos.remove('/tmp/unreachable')");
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(callable(&analysis.draft().calls()[0]), "os.execl");
}

#[test]
fn recursive_local_call_does_not_fall_through() {
    let analysis =
        analyze("import os\ndef recurse(): recurse()\nrecurse()\nos.remove('/tmp/unreachable')");
    assert!(analysis.draft().calls().is_empty());
    assert!(!analysis.draft().complete());
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
fn import_registry_barriers_are_partial_without_widening_host_state() {
    let analysis =
        analyze("import sys\nsys.modules.clear(1)\nopen('/home/dev/.nah/trust.json', 'w')");
    assert!(analysis.draft().calls().is_empty());

    let analysis = analyze(
        "import sys\ntry:\n    sys.modules.clear(1)\nexcept:\n    open('/tmp/caught', 'w')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/tmp/caught")
    );

    for mutation in [
        "sys.modules['shutil'] = replacement",
        "setattr(sys, 'modules', {})",
        "sys.__dict__['modules'] = {}",
        "registry = sys.modules\nregistry |= {}",
        "box = [sys.modules]\nbox[0]['shutil'] = replacement",
        "registry = sys.__dict__['modules']\nregistry['shutil'] = replacement",
        "sys.modules.clear()",
        "consume(sys.modules)",
    ] {
        let code =
            format!("import sys\n{mutation}\nimport shutil\nshutil.rmtree('/tmp/protected')");
        let analysis = analyze(&code);
        assert!(analysis.draft().calls().is_empty(), "{code}");
        assert!(!analysis.draft().complete(), "{code}");
    }

    for read in [
        "sys.modules['sys']",
        "sys.modules.get('shutil')",
        "sys.modules.keys()",
        "sys.modules.values()",
        "sys.modules.items()",
    ] {
        let code = format!("import sys\n{read}\nimport shutil\nshutil.rmtree('project-relative')");
        let analysis = analyze(&code);
        assert!(analysis.draft().complete(), "{code}");
        assert_eq!(analysis.draft().calls().len(), 1, "{code}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            Some("project-relative"),
            "{code}"
        );
    }

    let analysis = analyze(
        "import os, sys\nenv = os.environ\nsys.modules.clear()\nopen(env['HOME'] + '/.nah/trust.json', 'w')",
    );
    assert_eq!(analysis.draft().calls().len(), 1);
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("/home/dev/.nah/trust.json")
    );

    for source in [
        "import sys, shutil\nsys.__dict__['version'] = 'changed'\nshutil.rmtree('/tmp/protected')",
        "import sys, shutil\nbox = [sys.modules, {}]\nbox[1]['x'] = 1\nshutil.rmtree('/tmp/protected')",
        "import sys, shutil\nbox = [{}, sys.modules]\nbox[0]['x'] = 1\nshutil.rmtree('/tmp/protected')",
    ] {
        let analysis = analyze(source);
        assert_eq!(analysis.draft().calls().len(), 1, "{source}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            Some("/tmp/protected"),
            "{source}"
        );
    }

    for source in [
        "import sys, shutil\nbox = [sys.modules, None]\nbox[1].get('x')\nshutil.rmtree('/tmp/protected')",
        "import sys, shutil\nbox = [sys.modules]\nbox[9].get('x')\nshutil.rmtree('/tmp/protected')",
        "import sys, shutil\nbox = [None, sys.modules]\nbox[0].keys()\nshutil.rmtree('/tmp/protected')",
        "import sys, shutil\nsys.__dict__['version'].get('x')\nshutil.rmtree('/tmp/protected')",
        "import sys\nclear = sys.modules.clear\nsys.modules['x'] = object()\nclear(1)\nopen('/tmp/tail', 'w')",
        "import sys\nget = sys.modules.get\nsys.modules['x'] = object()\nget()\nopen('/tmp/tail', 'w')",
    ] {
        assert!(analyze(source).draft().calls().is_empty(), "{source}");
    }

    for source in [
        "import sys\nbox = [[sys.modules]]\ninner = box[0]\ninner[0]['shutil'] = replacement\nimport shutil\nshutil.rmtree('/tmp/protected')",
        "import sys\nbox = [sys.modules]\nregistry = box[index]\nregistry['shutil'] = replacement\nimport shutil\nshutil.rmtree('/tmp/protected')",
        "import sys\nregistry = sys.__dict__[key]\nregistry['shutil'] = replacement\nimport shutil\nshutil.rmtree('/tmp/protected')",
    ] {
        let analysis = analyze(source);
        assert!(analysis.draft().calls().is_empty(), "{source}");
        assert!(!analysis.draft().complete(), "{source}");
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
