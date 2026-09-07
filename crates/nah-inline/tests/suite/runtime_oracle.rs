#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::process::Command;

use nah_inline::{InlineInput, ProtectionInput, interpret_language_effects};
use nah_proto::action::FilesystemOperation;
use nah_proto::ctx::Platform;

#[derive(Debug, Eq, PartialEq)]
struct Effect {
    operation: &'static str,
    path: String,
}

fn predicted(program: &str, source: &str, complete: bool) -> Vec<Effect> {
    let analysis = interpret_language_effects(
        InlineInput {
            program,
            code: source,
            home: "/home/nah-oracle",
            platform: Platform::Linux,
        },
        ProtectionInput {
            critical_paths: &[],
            ambient_variables: &[],
        },
    );
    assert_eq!(analysis.draft().complete(), complete, "{program}: {source}");
    assert!(
        analysis.report().refusals().is_empty(),
        "{program}: {source}"
    );
    analysis
        .draft()
        .language_safety_calls()
        .iter()
        .flat_map(|call| call.filesystems())
        .map(|filesystem| Effect {
            operation: match filesystem.operation() {
                FilesystemOperation::Read => "read",
                FilesystemOperation::Write => "write",
                FilesystemOperation::Delete => "delete",
            },
            path: filesystem.requested().unwrap().to_owned(),
        })
        .collect()
}

fn actual(program: &str, script: &str, environment: &[(&str, &str)]) -> Vec<Effect> {
    let flag = if program == "node" { "-e" } else { "-c" };
    let output = Command::new(program)
        .args([flag, script])
        .envs(environment.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let (operation, path) = line.split_once('\t').unwrap();
            Effect {
                operation: match operation {
                    "read" => "read",
                    "write" => "write",
                    "delete" => "delete",
                    _ => panic!("unexpected oracle operation: {operation}"),
                },
                path: path.to_owned(),
            }
        })
        .collect()
}

fn python_script(source: &str) -> String {
    format!(
        r#"import builtins
_nah_trace = []
class _NahFile:
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def read(self, *_): return ''
    def write(self, value): return len(value)
def _nah_open(path, mode='r', *_args, **_kwargs):
    operation = 'read' if mode == 'r' else 'write'
    _nah_trace.append((operation, str(path)))
    return _NahFile()
builtins.open = _nah_open
{source}
for operation, path in _nah_trace:
    print(operation + '\t' + path)
"#
    )
}

fn node_script(source: &str) -> String {
    format!(
        r#"const _nahTrace = [];
const _nahFs = require('fs');
_nahFs.readFileSync = (path) => {{ _nahTrace.push(['read', String(path)]); return Buffer.from(''); }};
_nahFs.writeFileSync = (path) => {{ _nahTrace.push(['write', String(path)]); }};
_nahFs.rmSync = (path) => {{ _nahTrace.push(['delete', String(path)]); }};
{source}
for (const [operation, path] of _nahTrace) console.log(operation + '\t' + path);
"#
    )
}

#[test]
#[ignore = "nightly semantic oracle requires CPython and Node"]
fn supported_subset_matches_cpython_and_node() {
    let python_cases = [
        ("reader = open\nreader('/tmp/python-alias', 'r')", true),
        (
            "writer = open\ndef save(path):\n    writer(path, 'w')\nsave('/tmp/python-closure')",
            true,
        ),
        (
            "if False:\n    open('/tmp/python-unreachable', 'r')\ntry:\n    raise ValueError('stop')\nexcept ValueError:\n    open('/tmp/python-except', 'r')",
            false,
        ),
        (
            "reader = open\nopen = lambda *_: None\nreader('/tmp/python-captured', 'r')\nopen('/tmp/python-rebound', 'r')",
            true,
        ),
    ];
    for (source, complete) in python_cases {
        assert_eq!(
            predicted("python3", source, complete),
            actual("python3", &python_script(source), &[]),
            "python3: {source}"
        );
    }

    let node_cases = [
        (
            "const fs=require('fs');const write=fs.writeFileSync;write('/tmp/node-alias','x');",
            true,
        ),
        (
            "const fs=require('fs');function clean(){fs.rmSync('/tmp/node-closure',{recursive:true})}clean();",
            true,
        ),
        (
            "const fs=require('fs');if(false){fs.rmSync('/tmp/node-unreachable',{recursive:true})}try{throw 1}catch(error){fs.rmSync('/tmp/node-except',{recursive:true})}",
            true,
        ),
        (
            "const fs=require('fs');const write=fs.writeFileSync;fs.writeFileSync=()=>{};write('/tmp/node-captured','x');fs.writeFileSync('/tmp/node-rebound','x');",
            false,
        ),
    ];
    for (source, complete) in node_cases {
        assert_eq!(
            predicted("node", source, complete),
            actual("node", &node_script(source), &[]),
            "node: {source}"
        );
    }

    for (program, source, script) in [
        (
            "python3",
            "import os\nif os.getenv('NAH_ORACLE_FLAG') == 'yes':\n    open('/tmp/python-yes', 'r')\nelse:\n    open('/tmp/python-no', 'r')",
            python_script as fn(&str) -> String,
        ),
        (
            "node",
            "const fs=require('fs');if(process.env.NAH_ORACLE_FLAG==='yes'){fs.writeFileSync('/tmp/node-yes','x')}else{fs.writeFileSync('/tmp/node-no','x')}",
            node_script as fn(&str) -> String,
        ),
    ] {
        let possible = predicted(program, source, false);
        let observed = actual(program, &script(source), &[("NAH_ORACLE_FLAG", "yes")]);
        assert!(
            observed.iter().all(|effect| possible.contains(effect)),
            "{program}: observed={observed:?} possible={possible:?}"
        );
    }
}
