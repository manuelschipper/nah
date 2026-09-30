//! Patch and tool-call semantics: which file a patch names, and where a patch
//! the engine cannot read fails closed into one typed boundary rather than a
//! guess. These claims belong to the engine, so they are made against it.

use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{
    CoverageLevel, Domain, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject, ToolCall,
};

/// One tool call, analyzed as a consumer analyzes it.
fn analyze(tool: &str, args: &str, cwd: &str) -> Plan {
    analyze_in(tool, args, cwd, HostContext::default())
}

fn analyze_in(tool: &str, args: &str, cwd: &str, context: HostContext) -> Plan {
    let args: serde_json::Value = serde_json::from_str(args).unwrap();
    let call: ToolCall =
        serde_json::from_value(serde_json::json!({ "tool": tool, "args": args })).unwrap();
    let subject = Subject::ToolCall {
        call,
        cwd: Some(cwd.to_string()),
        context,
    };
    let plan = Engine::with_limits(default_limits())
        .unwrap()
        .analyze(&subject)
        .unwrap();
    effinterp_proto::validate_plan(&plan).unwrap();
    plan
}

#[test]
fn binary_marker_paths_do_not_override_git_preamble_paths() {
    let patch = concat!(
        "diff --git a/foo and bar.bin b/foo and bar.bin\n",
        "index 1111111..2222222 100644\n",
        "Binary files a/foo and bar.bin and b/foo and bar.bin differ\n",
    );
    let args = serde_json::json!({ "format": "unified", "text": patch }).to_string();
    let plan = analyze("file.patch", &args, "/work");

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.write");
    assert_eq!(
        plan.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/work/foo and bar.bin".to_string(),
            },
        }
    );
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn unified_noop_hunks_fail_closed() {
    for patch in [
        "--- a.txt\n+++ a.txt\n@@ -0,0 +0,0 @@\n",
        "--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n unchanged\n",
    ] {
        let args = serde_json::json!({ "format": "unified", "text": patch }).to_string();
        let plan = analyze("file.patch", &args, "/work");

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            effinterp_proto::BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::None
        );
    }
}

#[test]
fn malformed_git_status_metadata_fails_closed() {
    for patch in [
        concat!(
            "diff --git a/file.txt b/file.txt\n",
            "new file mode 100644\n",
            "--- a/file.txt\n",
            "+++ b/file.txt\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        ),
        concat!(
            "diff --git a/image.bin b/image.bin\n",
            "new file mode potato\n",
            "GIT binary patch\n",
            "literal 1\n",
            "A00000\n",
        ),
        concat!(
            "diff --git a/old.txt b/new.txt\n",
            "similarity index 100%\n",
            "rename from old.txt\n",
            "rename to new.txt\n",
            "--- /dev/null\n",
            "+++ b/new.txt\n",
            "@@ -0,0 +1 @@\n",
            "+new\n",
        ),
    ] {
        let args = serde_json::json!({ "format": "unified", "text": patch }).to_string();
        let plan = analyze("file.patch", &args, "/work");

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            effinterp_proto::BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(
            plan.coverage
                .0
                .iter()
                .map(|(d, claim)| (d.clone(), claim.level))
                .collect::<std::collections::BTreeMap<_, _>>(),
            std::collections::BTreeMap::from([(Domain::new("filesystem"), CoverageLevel::None,)])
        );
    }
}

#[test]
fn unified_null_side_hunk_lines_fail_closed() {
    for patch in [
        "--- /dev/null\n+++ created.txt\n@@ -1 +1 @@\n-old\n+new\n",
        "--- deleted.txt\n+++ /dev/null\n@@ -1 +1 @@\n-old\n+new\n",
    ] {
        let args = serde_json::json!({ "format": "unified", "text": patch }).to_string();
        let plan = analyze("file.patch", &args, "/work");

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            effinterp_proto::BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::None
        );
    }
}

#[test]
fn apply_patch_empty_add_is_a_valid_creation() {
    let patch = "*** Begin Patch\n*** Add File: empty.txt\n*** End Patch\n";
    let args = serde_json::json!({ "format": "apply_patch", "text": patch }).to_string();
    let plan = analyze("file.patch", &args, "/work");

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.create");
    assert_eq!(
        plan.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/work/empty.txt".to_string(),
            },
        }
    );
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn unified_timestamp_headers_preserve_trailing_path_spaces() {
    let patch = concat!(
        "--- new.txt \t2026-09-01 00:00:00 +0000\n",
        "+++ new.txt \t2026-09-01 00:00:00 +0000\n",
        "@@ -1 +1 @@\n",
        "-old\n",
        "+new\n",
    );
    let args = serde_json::json!({ "format": "unified", "text": patch }).to_string();
    let plan = analyze("file.patch", &args, "/work");

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(
        plan.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/work/new.txt ".to_string(),
            },
        }
    );
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn misplaced_unified_no_newline_markers_fail_closed() {
    let patch = concat!(
        "--- a.txt\n",
        "+++ a.txt\n",
        "@@ -1,2 +1,2 @@\n",
        " unchanged\n",
        "\\ No newline at end of file\n",
        "-old\n",
        "+new\n",
    );
    let args = serde_json::json!({ "format": "unified", "text": patch }).to_string();
    let plan = analyze("file.patch", &args, "/work");

    assert!(plan.effects.is_empty());
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(
        plan.boundaries[0].reason,
        effinterp_proto::BoundaryReason::PATCH_PARSE_FAILURE
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::None
    );
}

#[test]
fn plain_ab_patch_targets_the_stripped_path() {
    let args = serde_json::json!({"format":"unified", "text":"--- a/config.yml\n+++ b/config.yml\n@@ -1 +1 @@\n-old\n+new\n"}).to_string();
    let plan = analyze("file.patch", &args, "/workspace/project");
    assert_eq!(plan.effects[0].operation.0, "filesystem.write");
    assert_eq!(
        plan.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/workspace/project/config.yml".into()
            }
        }
    );
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn tool_paths_stay_literal_and_never_consult_host_environment() {
    let args = r#"{"path":"~/.aws/credentials"}"#;
    let literal = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/workspace/project/~/.aws/credentials".into(),
        },
    };
    let context = HostContext {
        env: [("HOME".to_string(), "/home/test".to_string())]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let with_home = analyze_in("file.read", args, "/workspace/project", context);
    assert_eq!(with_home.effects[0].resource, literal);
    // A literal tilde is not a host lookup, so HOME is never read to resolve it.
    assert!(!with_home.provenance.iter().any(
        |node| matches!(&node.kind, effinterp_proto::ProvenanceKind::HostContext { name } if name == "HOME")
    ));

    let without_home = analyze("file.read", args, "/workspace/project");
    assert_eq!(without_home.effects[0].resource, literal);
    assert!(without_home.boundaries.is_empty());
}
