use std::collections::BTreeMap;

use effinterp_engine::{Engine, EngineError, default_limits};
use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, FileDeleteArgs, FileEditArgs,
    FileEditBatchArgs, FileEditEntry, FilePatchArgs, FileReadArgs, FileTransferArgs, FileWriteArgs,
    FsFindArgs, FsGlobArgs, FsGrepArgs, FsListArgs, HostContext, LineRange, PatchFormat,
    ProvenanceKind, ResourceExpr, ResourceIdentity, Subject, ToolCall, TransferDirection,
    UnknownToolArgs, canonical_json, validate_plan,
};

fn subject(call: ToolCall, cwd: Option<&str>) -> Subject {
    Subject::ToolCall {
        call,
        cwd: cwd.map(str::to_string),
        context: HostContext::default(),
    }
}

fn path(resource: &ResourceExpr) -> Option<&str> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn provenance_names<'a>(
    plan: &'a effinterp_proto::Plan,
    roots: &[effinterp_proto::ProvenanceRef],
) -> Vec<&'a str> {
    roots
        .iter()
        .filter_map(|root| match &plan.provenance[root.0 as usize].kind {
            ProvenanceKind::ToolArgument { name } => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn direct_file_tools_lower_to_typed_filesystem_effects() {
    let engine = Engine::new();
    let read = engine
        .analyze(&subject(
            ToolCall::FileRead(FileReadArgs {
                path: "src/lib.rs".to_string(),
                range: Some(LineRange {
                    start_line: 2,
                    end_line: Some(4),
                }),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert_eq!(read.effects.len(), 1);
    assert_eq!(read.effects[0].operation.0, "filesystem.read");
    assert_eq!(path(&read.effects[0].resource), Some("/work/src/lib.rs"));
    assert_eq!(
        read.effects[0].attributes["range"],
        AttrValue::String("lines:2-4".to_string())
    );
    assert_eq!(
        provenance_names(&read, &read.effects[0].provenance),
        ["path", "range"]
    );
    assert_eq!(
        read.coverage
            .0
            .iter()
            .map(|(domain, claim)| (domain.clone(), claim.level))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([(Domain::new("filesystem"), CoverageLevel::Full)])
    );

    let write = engine
        .analyze(&subject(
            ToolCall::FileWrite(FileWriteArgs {
                path: "/tmp/é".to_string(),
                content: "aé".to_string(),
            }),
            None,
        ))
        .unwrap();
    assert_eq!(write.effects[0].operation.0, "filesystem.write");
    assert_eq!(write.effects[0].attributes["bytes"], AttrValue::Int(3));
    assert_eq!(
        write.effects[0].attributes["create"],
        AttrValue::String("may".to_string())
    );
    assert_eq!(
        write.effects[0].attributes["truncate"],
        AttrValue::Bool(true)
    );
    assert_eq!(
        provenance_names(&write, &write.effects[0].provenance),
        ["path", "content"]
    );

    let delete_subject = subject(
        ToolCall::FileDelete(FileDeleteArgs {
            path: "old\nfile".to_string(),
        }),
        Some("/work"),
    );
    assert_eq!(
        serde_json::from_value::<Subject>(serde_json::to_value(&delete_subject).unwrap()).unwrap(),
        delete_subject
    );
    let delete = engine.analyze(&delete_subject).unwrap();
    assert_eq!(delete.effects.len(), 1);
    assert_eq!(delete.effects[0].operation.0, "filesystem.delete");
    assert_eq!(path(&delete.effects[0].resource), Some("/work/old\nfile"));
    assert_eq!(
        delete.effects[0].attributes["recursive"],
        AttrValue::Bool(false)
    );
    assert_eq!(
        provenance_names(&delete, &delete.effects[0].provenance),
        ["path"]
    );
    assert_eq!(
        delete.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
    validate_plan(&delete).unwrap();

    let edit = engine
        .analyze(&subject(
            ToolCall::FileEdit(FileEditArgs {
                path: "/tmp/file".to_string(),
                old: String::new(),
                new: "insert".to_string(),
                count: Some(2),
            }),
            None,
        ))
        .unwrap();
    assert_eq!(
        edit.effects
            .iter()
            .map(|effect| effect.operation.0.as_str())
            .collect::<Vec<_>>(),
        ["filesystem.read", "filesystem.write"]
    );
    for effect in &edit.effects {
        assert_eq!(effect.attributes["in_place"], AttrValue::Bool(true));
        assert_eq!(effect.attributes["old_bytes"], AttrValue::Int(0));
        assert_eq!(effect.attributes["new_bytes"], AttrValue::Int(6));
        assert_eq!(effect.attributes["occurrences"], AttrValue::Int(2));
        assert_eq!(effect.modality, effinterp_proto::Modality::May);
        assert!(effect.realm.is_host());
    }
}

#[test]
fn partial_file_transfers_keep_local_side_and_bound_remote_target() {
    for (direction, local_operation, network_operation) in [
        (
            TransferDirection::Upload,
            "filesystem.read",
            "network.upload",
        ),
        (
            TransferDirection::Download,
            "filesystem.write",
            "network.download",
        ),
    ] {
        let (source_operation, destination_operation) = match direction {
            TransferDirection::Upload => (local_operation, network_operation),
            TransferDirection::Download => (network_operation, local_operation),
        };
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&subject(
                ToolCall::FileTransfer(FileTransferArgs {
                    path: "/repo/$literal".into(),
                    direction,
                }),
                Some("/work"),
            ))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(plan.effects.len(), 2);
        assert_eq!(plan.effects[0].operation.0, local_operation);
        assert_eq!(path(&plan.effects[0].resource), Some("/repo/$literal"));
        assert_eq!(plan.effects[1].operation.0, network_operation);
        assert!(matches!(
            &plan.effects[1].resource,
            ResourceExpr::Unresolved { family } if family.0 == "net"
        ));
        assert_eq!(
            plan.effects[0].attributes["transfer_direction"],
            AttrValue::String(
                match direction {
                    TransferDirection::Upload => "upload",
                    TransferDirection::Download => "download",
                }
                .into()
            )
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Full
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("network")].level,
            CoverageLevel::Partial
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason == BoundaryReason::UNRESOLVED_TRANSFER_TARGET)
        );
        let graph = plan.causality.graph.as_ref().expect("causality graph");
        assert!(graph.edges.iter().any(|edge| {
            edge.reason == effinterp_proto::CausalReason::ResourceTransfer
                && edge.assurance == effinterp_proto::CausalAssurance::Exact
                && graph.nodes.iter().any(|node| {
                    node.id == edge.from
                        && matches!(
                            &node.occurrence,
                            effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. }
                                if operation.0 == source_operation
                        )
                })
                && graph.nodes.iter().any(|node| {
                    node.id == edge.to
                        && matches!(
                            &node.occurrence,
                            effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. }
                                if operation.0 == destination_operation
                        )
                })
        }));
    }
}

#[test]
fn search_and_listing_tools_retain_patterns_filters_and_paths() {
    let engine = Engine::new();
    let glob = engine
        .analyze(&subject(
            ToolCall::FsGlob(FsGlobArgs {
                pattern: "**/*.rs".to_string(),
                root: Some("src".to_string()),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert!(matches!(
        &glob.effects[0].resource,
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } }
            if pattern == "/work/src/**/*.rs"
    ));

    let unknown_root = engine
        .analyze(&subject(
            ToolCall::FsGlob(FsGlobArgs {
                pattern: "*.rs".into(),
                root: None,
            }),
            None,
        ))
        .unwrap();
    validate_plan(&unknown_root).unwrap();
    assert!(
        matches!(&unknown_root.effects[0].resource, ResourceExpr::Join { parts }
        if matches!(&parts[0], ResourceExpr::Parameter { name } if name == "cwd"))
    );
    let absolute = engine
        .analyze(&subject(
            ToolCall::FsGlob(FsGlobArgs {
                pattern: "/src/*.rs".into(),
                root: Some("/other".into()),
            }),
            None,
        ))
        .unwrap();
    assert!(
        matches!(&absolute.effects[0].resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/src/*.rs")
    );
    let invalid = engine
        .analyze(&subject(
            ToolCall::FsGlob(FsGlobArgs {
                pattern: "*/../x".into(),
                root: None,
            }),
            None,
        ))
        .unwrap();
    validate_plan(&invalid).unwrap();
    assert!(!invalid.boundaries.is_empty());

    let grep = engine
        .analyze(&subject(
            ToolCall::FsGrep(FsGrepArgs {
                pattern: "unsafe".to_string(),
                paths: Some(vec!["lib.rs".to_string(), "main.rs".to_string()]),
                root: Some("src".to_string()),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert_eq!(grep.effects.len(), 2);
    assert_eq!(path(&grep.effects[0].resource), Some("/work/src/lib.rs"));
    assert_eq!(path(&grep.effects[1].resource), Some("/work/src/main.rs"));
    assert_eq!(
        grep.effects[0].attributes["content_filter"],
        AttrValue::String("unsafe".to_string())
    );
    assert_eq!(
        provenance_names(&grep, &grep.effects[1].provenance),
        ["paths[1]", "pattern", "root"]
    );

    let subtree = engine
        .analyze(&subject(
            ToolCall::FsGrep(FsGrepArgs {
                pattern: "needle".to_string(),
                paths: None,
                root: None,
            }),
            Some("/work"),
        ))
        .unwrap();
    assert!(matches!(
        &subtree.effects[0].resource,
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/work/**"
    ));
    let ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
    } = &subtree.effects[0].resource
    else {
        unreachable!()
    };
    for path in ["/work/a/b", "/work/.hidden", "/work/.hidden/a"] {
        assert_eq!(effinterp_proto::glob_match(pattern, path), Ok(true));
    }

    let list = engine
        .analyze(&subject(
            ToolCall::FsList(FsListArgs {
                path: "/work/src".to_string(),
            }),
            None,
        ))
        .unwrap();
    assert_eq!(
        list.effects[0].attributes["metadata"],
        AttrValue::Bool(true)
    );
}

#[test]
fn batch_edit_preserves_order_and_bounds_without_synthesizing_a_patch() {
    let engine = Engine::new();
    let plan = engine
        .analyze(&subject(
            ToolCall::FileEditBatch(FileEditBatchArgs {
                path: "/work/file".into(),
                edits: vec![
                    FileEditEntry {
                        old: "one".into(),
                        new: "ONE".into(),
                    },
                    FileEditEntry {
                        old: "two".into(),
                        new: "TWO".into(),
                    },
                ],
            }),
            None,
        ))
        .unwrap();
    assert_eq!(
        plan.effects
            .iter()
            .map(|effect| effect.operation.0.as_str())
            .collect::<Vec<_>>(),
        [
            "filesystem.read",
            "filesystem.write",
            "filesystem.read",
            "filesystem.write"
        ]
    );
    assert_eq!(plan.effects[0].attributes["batch_index"], AttrValue::Int(0));
    assert_eq!(plan.effects[2].attributes["batch_index"], AttrValue::Int(1));
    assert_eq!(
        provenance_names(&plan, &plan.effects[2].provenance),
        ["path", "edits[1].old", "edits[1].new"]
    );
    assert!(plan.boundaries.is_empty());
    validate_plan(&plan).unwrap();

    let plan = engine
        .analyze(&subject(
            ToolCall::FileEditBatch(FileEditBatchArgs {
                path: "/work/file".into(),
                edits: (0..65)
                    .map(|index| FileEditEntry {
                        old: format!("old-{index}"),
                        new: format!("new-{index}"),
                    })
                    .collect(),
            }),
            None,
        ))
        .unwrap();
    assert_eq!(
        plan.effects
            .iter()
            .map(|effect| effect.operation.0.as_str())
            .collect::<Vec<_>>(),
        ["filesystem.read", "filesystem.write"]
    );
    assert!(plan.effects.iter().all(|effect| {
        effect.attributes["batch"] == AttrValue::Bool(true)
            && effect.attributes["occurrences"] == AttrValue::String("unknown".into())
    }));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason == BoundaryReason::LIMIT_SATURATED
            && boundary.limit.as_deref() == Some("file_edit_batch_entries")
    }));
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Partial
    );
    validate_plan(&plan).unwrap();
}

#[test]
fn recursive_find_is_name_selection_with_a_bounded_result_hint() {
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FsFind(FsFindArgs {
                pattern: "*.rs".into(),
                root: "/work/src".into(),
                limit: Some(10),
            }),
            None,
        ))
        .unwrap();
    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.read");
    assert_eq!(
        plan.effects[0].attributes["recursive"],
        AttrValue::Bool(true)
    );
    assert_eq!(
        plan.effects[0].attributes["selection_limit"],
        AttrValue::Int(10)
    );
    assert_eq!(
        plan.effects[0].attributes["filename_selector"],
        AttrValue::String("*.rs".into())
    );
    assert!(!plan.effects[0].attributes.contains_key("content_filter"));
    assert!(matches!(
        &plan.effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/work/src"
    ));
    assert!(
        plan.causality
            .graph
            .as_ref()
            .is_none_or(|graph| graph.edges.is_empty())
    );
    validate_plan(&plan).unwrap();
}

#[test]
fn native_tool_paths_are_literal_with_cwd_bounds() {
    let symbolic = Subject::ToolCall {
        call: ToolCall::FileRead(FileReadArgs {
            path: "~/src/$NAME.rs".to_string(),
            range: None,
        }),
        cwd: Some("/work".to_string()),
        context: HostContext::default(),
    };
    let plan = Engine::new().analyze(&symbolic).unwrap();
    assert_eq!(
        path(&plan.effects[0].resource),
        Some("/work/~/src/$NAME.rs")
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
    assert!(plan.boundaries.is_empty());

    let unknown_cwd = Engine::new()
        .analyze(&subject(
            ToolCall::FileRead(FileReadArgs {
                path: "relative".to_string(),
                range: None,
            }),
            None,
        ))
        .unwrap();
    assert!(matches!(
        &unknown_cwd.effects[0].resource,
        ResourceExpr::Join { parts }
            if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")
    ));
}

#[test]
fn unknown_tools_are_explicitly_unsupported_across_all_domains() {
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::Unknown(UnknownToolArgs {
                name: "RuntimeFetch".to_string(),
                args: serde_json::json!({"url":"https://example.test"}),
            }),
            None,
        ))
        .unwrap();
    assert!(plan.effects.is_empty());
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(plan.boundaries[0].reason, BoundaryReason::UNSUPPORTED_TOOL);
    assert_eq!(plan.boundaries[0].class, BoundaryClass::Unsupported);
    assert_eq!(plan.boundaries[0].detail.as_deref(), Some("RuntimeFetch"));
    assert_eq!(
        plan.boundaries[0].domains.len(),
        effinterp_proto::DOMAINS.len()
    );
    assert!(
        plan.coverage
            .0
            .values()
            .all(|level| level.level == CoverageLevel::None)
    );
}

#[test]
fn unified_and_apply_patch_lower_file_operations_without_reading_files() {
    let unified = concat!(
        "--- /dev/null\n",
        "+++ added.txt\n",
        "@@ -0,0 +1 @@\n",
        "+added\n",
        "--- deleted.txt\n",
        "+++ /dev/null\n",
        "@@ -1 +0,0 @@\n",
        "-gone\n",
        "--- changed.txt\n",
        "+++ changed.txt\n",
        "@@ -1 +1 @@\n",
        "-old\n",
        "\\ No newline at end of file\n",
        "+new\n",
        "\\ No newline at end of file\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: unified.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert_eq!(
        plan.effects
            .iter()
            .map(|effect| (effect.operation.0.as_str(), path(&effect.resource).unwrap()))
            .collect::<Vec<_>>(),
        [
            ("filesystem.create", "/work/added.txt"),
            ("filesystem.delete", "/work/deleted.txt"),
            ("filesystem.write", "/work/changed.txt"),
        ]
    );
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.attributes["hunks"] == AttrValue::Int(1))
    );
    assert_eq!(
        plan.effects[2].attributes["in_place"],
        AttrValue::Bool(true)
    );

    let apply = concat!(
        "*** Begin Patch\n",
        "*** Add File: added.txt\n",
        "+hello\n",
        "*** Delete File: deleted.txt\n",
        "*** Update File: old.txt\n",
        "*** Move to: moved.txt\n",
        "@@\n",
        "-old\n",
        "+new\n",
        "*** End Patch\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::ApplyPatch,
                text: apply.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert_eq!(
        plan.effects
            .iter()
            .map(|effect| (effect.operation.0.as_str(), path(&effect.resource).unwrap()))
            .collect::<Vec<_>>(),
        [
            ("filesystem.create", "/work/added.txt"),
            ("filesystem.delete", "/work/deleted.txt"),
            ("filesystem.move", "/work/old.txt"),
            ("filesystem.write", "/work/moved.txt"),
        ]
    );
    assert_eq!(
        plan.effects[3].attributes["move_destination"],
        AttrValue::Bool(true)
    );
    assert!(
        plan.effects
            .iter()
            .all(|effect| { provenance_names(&plan, &effect.provenance) == ["text"] })
    );
}

#[test]
fn apply_patch_empty_add_lowers_to_zero_byte_creation() {
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::ApplyPatch,
                text: concat!(
                    "*** Begin Patch\n",
                    "*** Add File: empty.txt\n",
                    "*** End Patch\n",
                )
                .to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.create");
    assert_eq!(path(&plan.effects[0].resource), Some("/work/empty.txt"));
    assert_eq!(plan.effects[0].attributes["hunks"], AttrValue::Int(0));
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn git_rename_and_binary_sections_are_bounded_structural_operations() {
    let patch = concat!(
        "diff --git a/old.txt b/new.txt\n",
        "similarity index 100%\n",
        "rename from old.txt\n",
        "rename to new.txt\n",
        "diff --git a/image.bin b/image.bin\n",
        "index 1111111..2222222 100644\n",
        "Binary files a/image.bin and b/image.bin differ\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: patch.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert_eq!(plan.effects.len(), 3);
    assert_eq!(plan.effects[0].operation.0, "filesystem.move");
    assert_eq!(plan.effects[1].operation.0, "filesystem.write");
    assert_eq!(plan.effects[2].operation.0, "filesystem.write");
    assert_eq!(plan.effects[2].attributes["hunks"], AttrValue::Int(0));
}

#[test]
fn valid_git_status_metadata_matches_file_headers() {
    let patch = concat!(
        "diff --git a/created.txt b/created.txt\n",
        "new file mode 100644\n",
        "index 0000000..1111111\n",
        "--- /dev/null\n",
        "+++ b/created.txt\n",
        "@@ -0,0 +1 @@\n",
        "+new\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: patch.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.create");
    assert_eq!(path(&plan.effects[0].resource), Some("/work/created.txt"));
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage
            .0
            .iter()
            .map(|(d, claim)| (d.clone(), claim.level))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([(Domain::new("filesystem"), CoverageLevel::Full)])
    );
}

#[test]
fn binary_marker_paths_do_not_override_git_preamble_paths() {
    let patch = concat!(
        "diff --git a/foo and bar.bin b/foo and bar.bin\n",
        "index 1111111..2222222 100644\n",
        "Binary files a/foo and bar.bin and b/foo and bar.bin differ\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: patch.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.write");
    assert_eq!(
        path(&plan.effects[0].resource),
        Some("/work/foo and bar.bin")
    );
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn git_preamble_paths_with_spaces_lower_from_file_headers() {
    let patch = concat!(
        "diff --git a/new name.txt b/new name.txt\n",
        "index 3367afd..3e75765 100644\n",
        "--- a/new name.txt\n",
        "+++ b/new name.txt\n",
        "@@ -1 +1 @@\n",
        "-old\n",
        "+new\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: patch.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(plan.effects[0].operation.0, "filesystem.write");
    assert_eq!(path(&plan.effects[0].resource), Some("/work/new name.txt"));
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn ambiguous_git_preamble_paths_fail_closed() {
    let patch = concat!(
        "diff --git a/dir b/bin/true b/dir b/bin/false\n",
        "index 1111111..2222222 100755\n",
        "GIT binary patch\n",
        "literal 1\n",
        "A00000\n",
    );
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: patch.to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();

    assert!(plan.effects.is_empty());
    assert_eq!(
        plan.boundaries[0].reason,
        BoundaryReason::PATCH_PARSE_FAILURE
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::None
    );
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
        let plan = Engine::new()
            .analyze(&subject(
                ToolCall::FilePatch(FilePatchArgs {
                    format: PatchFormat::Unified,
                    text: patch.to_string(),
                }),
                Some("/work"),
            ))
            .unwrap();

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(plan.boundaries[0].class, BoundaryClass::ParseFailure);
        assert_eq!(
            plan.coverage
                .0
                .iter()
                .map(|(d, claim)| (d.clone(), claim.level))
                .collect::<BTreeMap<_, _>>(),
            BTreeMap::from([(Domain::new("filesystem"), CoverageLevel::None)])
        );
    }
}

#[test]
fn tool_effect_saturation_degrades_only_filesystem_coverage() {
    let max_effects = default_limits()["max_effects"];
    let paths = (0..=max_effects)
        .map(|index| format!("file-{index}"))
        .collect();
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FsGrep(FsGrepArgs {
                pattern: "needle".to_string(),
                paths: Some(paths),
                root: None,
            }),
            Some("/work"),
        ))
        .unwrap();

    validate_plan(&plan).unwrap();
    assert_eq!(plan.effects.len() as u64, max_effects);
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(plan.boundaries[0].reason, BoundaryReason::LIMIT_SATURATED);
    assert_eq!(plan.boundaries[0].limit.as_deref(), Some("max_effects"));
    assert_eq!(plan.boundaries[0].domains, vec![Domain::new("filesystem")]);
    assert_eq!(
        plan.coverage
            .0
            .iter()
            .map(|(d, claim)| (d.clone(), claim.level))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([(Domain::new("filesystem"), CoverageLevel::Partial)])
    );
}

#[test]
fn tool_boundary_and_provenance_saturation_degrade_only_filesystem_coverage() {
    for (limit, maximum, paths) in [
        (
            "max_boundaries",
            1,
            vec!["$FIRST".to_string(), "$SECOND".to_string()],
        ),
        (
            "max_provenance_nodes",
            2,
            vec!["first".to_string(), "second".to_string()],
        ),
    ] {
        let mut limits = default_limits();
        limits.insert(limit.to_string(), maximum);
        let plan = Engine::with_limits(limits)
            .unwrap()
            .analyze(&subject(
                ToolCall::FsGrep(FsGrepArgs {
                    pattern: "needle".to_string(),
                    paths: Some(paths),
                    root: None,
                }),
                None,
            ))
            .unwrap();

        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.limit.as_deref() == Some(limit))
        );
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.domains == [Domain::new("filesystem")])
        );
        assert_eq!(
            plan.coverage
                .0
                .iter()
                .map(|(d, claim)| (d.clone(), claim.level))
                .collect::<BTreeMap<_, _>>(),
            BTreeMap::from([(Domain::new("filesystem"), CoverageLevel::Partial)])
        );
    }
}

#[test]
fn malformed_and_saturated_patches_emit_no_effects_and_none_coverage() {
    let malformed = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: "--- a\n+++ a\n@@ -1 +1 @@\n+new\n".to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert!(malformed.effects.is_empty());
    assert_eq!(
        malformed.boundaries[0].reason,
        BoundaryReason::PATCH_PARSE_FAILURE
    );
    assert_eq!(malformed.boundaries[0].class, BoundaryClass::ParseFailure);
    assert_eq!(
        malformed.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::None
    );

    let mut byte_limits = default_limits();
    byte_limits.insert("max_patch_bytes".to_string(), 5);
    let saturated = Engine::with_limits(byte_limits)
        .unwrap()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::ApplyPatch,
                text: "*** Begin Patch\n*** Delete File: x\n*** End Patch\n".to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert!(saturated.effects.is_empty());
    assert_eq!(
        saturated.boundaries[0].reason,
        BoundaryReason::LIMIT_SATURATED
    );
    assert_eq!(
        saturated.boundaries[0].limit.as_deref(),
        Some("max_patch_bytes")
    );

    let mut file_limits = default_limits();
    file_limits.insert("max_patch_files".to_string(), 1);
    let saturated = Engine::with_limits(file_limits)
        .unwrap()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::ApplyPatch,
                text: concat!(
                    "*** Begin Patch\n",
                    "*** Delete File: a\n",
                    "*** Delete File: b\n",
                    "*** End Patch\n",
                )
                .to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();
    assert!(saturated.effects.is_empty());
    assert_eq!(
        saturated.boundaries[0].limit.as_deref(),
        Some("max_patch_files")
    );
}

#[test]
fn unified_noop_hunks_fail_closed() {
    for text in [
        "--- a.txt\n+++ a.txt\n@@ -0,0 +0,0 @@\n",
        "--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n unchanged\n",
    ] {
        let plan = Engine::new()
            .analyze(&subject(
                ToolCall::FilePatch(FilePatchArgs {
                    format: PatchFormat::Unified,
                    text: text.to_string(),
                }),
                Some("/work"),
            ))
            .unwrap();

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(plan.boundaries[0].class, BoundaryClass::ParseFailure);
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::None
        );
    }
}

#[test]
fn unified_null_side_hunk_lines_fail_closed() {
    for text in [
        "--- /dev/null\n+++ created.txt\n@@ -1 +1 @@\n-old\n+new\n",
        "--- deleted.txt\n+++ /dev/null\n@@ -1 +1 @@\n-old\n+new\n",
    ] {
        let plan = Engine::new()
            .analyze(&subject(
                ToolCall::FilePatch(FilePatchArgs {
                    format: PatchFormat::Unified,
                    text: text.to_string(),
                }),
                Some("/work"),
            ))
            .unwrap();

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(plan.boundaries[0].class, BoundaryClass::ParseFailure);
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::None
        );
    }
}

#[test]
fn unified_headers_preserve_path_bytes_before_timestamps() {
    let plan = Engine::new()
        .analyze(&subject(
            ToolCall::FilePatch(FilePatchArgs {
                format: PatchFormat::Unified,
                text: concat!(
                    "--- new.txt \t2026-09-01 00:00:00 +0000\n",
                    "+++ new.txt \t2026-09-01 00:00:00 +0000\n",
                    "@@ -1 +1 @@\n",
                    "-old\n",
                    "+new\n",
                )
                .to_string(),
            }),
            Some("/work"),
        ))
        .unwrap();

    assert_eq!(plan.effects.len(), 1);
    assert_eq!(path(&plan.effects[0].resource), Some("/work/new.txt "));
    assert!(plan.boundaries.is_empty());
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
}

#[test]
fn unified_no_newline_markers_must_follow_a_terminal_line() {
    for hunk in [
        concat!(
            "@@ -1,2 +1,2 @@\n",
            " unchanged\n",
            "\\ No newline at end of file\n",
            "-old\n",
            "+new\n",
        ),
        concat!(
            "@@ -1,2 +1 @@\n",
            "-old\n",
            "\\ No newline at end of file\n",
            "-more\n",
            "+new\n",
        ),
        concat!(
            "@@ -1 +1,2 @@\n",
            "-old\n",
            "+new\n",
            "\\ No newline at end of file\n",
            "+more\n",
        ),
    ] {
        let plan = Engine::new()
            .analyze(&subject(
                ToolCall::FilePatch(FilePatchArgs {
                    format: PatchFormat::Unified,
                    text: format!("--- a.txt\n+++ a.txt\n{hunk}"),
                }),
                Some("/work"),
            ))
            .unwrap();

        assert!(plan.effects.is_empty());
        assert_eq!(plan.boundaries.len(), 1);
        assert_eq!(
            plan.boundaries[0].reason,
            BoundaryReason::PATCH_PARSE_FAILURE
        );
        assert_eq!(plan.boundaries[0].class, BoundaryClass::ParseFailure);
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::None
        );
    }
}

#[test]
fn tool_call_analysis_is_deterministic_and_rejects_manual_invalid_subjects() {
    let valid_subject = subject(
        ToolCall::FileWrite(FileWriteArgs {
            path: "/tmp/x".to_string(),
            content: "secret body".to_string(),
        }),
        None,
    );
    let engine = Engine::new();
    let first = engine.analyze(&valid_subject).unwrap();
    let second = engine.analyze(&valid_subject).unwrap();
    assert_eq!(canonical_json(&first), canonical_json(&second));

    let invalid = subject(
        ToolCall::FileEdit(FileEditArgs {
            path: "/tmp/x".to_string(),
            old: "a".to_string(),
            new: "b".to_string(),
            count: Some(0),
        }),
        None,
    );
    assert!(matches!(
        engine.analyze(&invalid),
        Err(EngineError::InvalidSubject(_))
    ));
}

#[test]
fn native_globs_preserve_literal_roots() {
    for pattern in ["${HOME}/*.rs", "~/*.rs"] {
        let plan = Engine::new()
            .analyze(&subject(
                ToolCall::FsGlob(FsGlobArgs {
                    pattern: pattern.into(),
                    root: Some("/ignored".into()),
                }),
                Some("/work"),
            ))
            .unwrap();
        validate_plan(&plan).unwrap();
        let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } = &plan.effects[0].resource
        else {
            panic!("expected literal filesystem pattern");
        };
        assert_eq!(glob, &format!("/ignored/{pattern}"));
        assert!(
            plan.provenance
                .iter()
                .all(|node| !matches!(node.kind, ProvenanceKind::HostContext { .. }))
        );
    }
    for cwd in [None, Some("/work")] {
        for root in [None, Some("/explicit")] {
            for (operand, target) in [
                ("../build/*.rs", "/build/x.rs".to_string()),
                ("/w/../y/*.rs", "/y/x.rs".to_string()),
                (
                    "./tmp//./*.rs",
                    format!("{}/tmp/x.rs", root.or(cwd).unwrap_or("")),
                ),
                (r"\/tmp/*.rs", "/tmp/x.rs".to_string()),
                ("/tmp/*.rs", "/tmp/x.rs".to_string()),
                (
                    "tmp/*.rs",
                    format!("{}/tmp/x.rs", root.or(cwd).unwrap_or("")),
                ),
                (
                    r"\\/tmp/*.rs",
                    format!(r"{}/\/tmp/x.rs", root.or(cwd).unwrap_or("")),
                ),
            ] {
                let plan = Engine::new()
                    .analyze(&subject(
                        ToolCall::FsGlob(FsGlobArgs {
                            pattern: operand.to_string(),
                            root: root.map(str::to_string),
                        }),
                        cwd,
                    ))
                    .unwrap();
                validate_plan(&plan).unwrap();
                if !operand.starts_with('/')
                    && !operand.starts_with(r"\/")
                    && root.is_none()
                    && cwd.is_none()
                {
                    assert!(matches!(
                        &plan.effects[0].resource,
                        ResourceExpr::Join { .. }
                    ));
                    continue;
                }
                let ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
                } = &plan.effects[0].resource
                else {
                    panic!("expected rooted glob");
                };
                assert_eq!(
                    effinterp_proto::glob_match(pattern, &target),
                    Ok(true),
                    "{operand:?}, root={root:?}, cwd={cwd:?}: {pattern:?}"
                );
                if target == "/tmp/x.rs" {
                    assert_eq!(pattern, operand);
                    assert_eq!(
                        effinterp_proto::glob_match(pattern, "/work/tmp/x.rs"),
                        Ok(false)
                    );
                }
            }
        }
    }

    for root in ["/tmp/[ab]", r"/tmp/a\b", "/tmp/a*b?", "/tmp/plain"] {
        for explicit_root in [None, Some(root.to_string())] {
            let plan = Engine::new()
                .analyze(&subject(
                    ToolCall::FsGlob(FsGlobArgs {
                        pattern: "*.rs".to_string(),
                        root: explicit_root,
                    }),
                    Some(root),
                ))
                .unwrap();
            validate_plan(&plan).unwrap();
            let ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
            } = &plan.effects[0].resource
            else {
                panic!("expected rooted glob");
            };
            assert_eq!(
                effinterp_proto::glob_match(pattern, &format!("{root}/x.rs")),
                Ok(true)
            );
            assert_eq!(
                effinterp_proto::glob_match(pattern, &format!("{root}/x.txt")),
                Ok(false)
            );
        }
    }
}

#[test]
fn host_context_does_not_expand_typed_tool_paths() {
    for call in [
        ToolCall::FileRead(FileReadArgs {
            path: "/repo/$literal".into(),
            range: None,
        }),
        ToolCall::FileRead(FileReadArgs {
            path: "~/literal".into(),
            range: None,
        }),
        ToolCall::FsGlob(FsGlobArgs {
            pattern: "$HOME/*.rs".into(),
            root: Some("~/src".into()),
        }),
    ] {
        let mut input = subject(call, Some("/work"));
        if let Subject::ToolCall { context, .. } = &mut input {
            context.env.insert("HOME".into(), "/home/test".into());
        }
        let plan = Engine::new().analyze(&input).unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.provenance
                .iter()
                .all(|node| !matches!(node.kind, ProvenanceKind::HostContext { .. }))
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "environment.read")
        );
    }
}

#[test]
fn unused_host_context_preserves_typed_tool_semantics() {
    for (tool, args) in [
        ("file.read", serde_json::json!({"path":"~/x"})),
        (
            "file.write",
            serde_json::json!({"path":"$HOME/x","content":"abc"}),
        ),
        (
            "file.edit",
            serde_json::json!({"path":"${HOME}/x","old":"a","new":"b"}),
        ),
        (
            "file.patch",
            serde_json::json!({"format":"unified","text":"--- ~/x\n+++ ~/x\n@@ -1 +1 @@\n-a\n+b\n"}),
        ),
        (
            "fs.glob",
            serde_json::json!({"pattern":"*.pem","root":"~/keys"}),
        ),
        (
            "fs.grep",
            serde_json::json!({"pattern":"secret","paths":["~/a"],"root":"$DIR"}),
        ),
        ("fs.list", serde_json::json!({"path":"~/x"})),
        (
            "tool.unknown",
            serde_json::json!({"name":"custom","args":{}}),
        ),
    ] {
        let call: ToolCall =
            serde_json::from_value(serde_json::json!({"tool":tool,"args":args})).unwrap();
        let mut input = subject(call, Some("/work"));
        let empty = Engine::new().analyze(&input).unwrap();
        if let Subject::ToolCall { context, .. } = &mut input {
            context.env.insert("UNUSED".into(), "1".into());
        }
        let unused = Engine::new().analyze(&input).unwrap();
        assert_eq!(empty.effects.len(), unused.effects.len());
        for (empty, unused) in empty.effects.iter().zip(&unused.effects) {
            assert_ne!(empty.id, unused.id);
        }
        assert_eq!(empty.provenance, unused.provenance);
        assert_eq!(empty.boundaries, unused.boundaries);
        assert_eq!(empty.coverage, unused.coverage);
        let mut empty_json: serde_json::Value =
            serde_json::from_str(&canonical_json(&empty)).unwrap();
        let mut unused_json: serde_json::Value =
            serde_json::from_str(&canonical_json(&unused)).unwrap();
        for document in [&mut empty_json, &mut unused_json] {
            for effect in document["effects"].as_array_mut().unwrap() {
                effect.as_object_mut().unwrap().remove("id");
            }
        }
        for field in ["effects", "provenance", "boundaries", "coverage"] {
            assert_eq!(empty_json[field], unused_json[field], "{tool}: {field}");
        }
    }
}

#[test]
fn unified_prefix_table() {
    let hunk = "@@ -1 +1 @@\n-old\n+new\n";
    let mut cases = Vec::new();
    for (old, new, target) in [
        ("a/config.yml", "b/config.yml", Some("config.yml")),
        ("a/config.yml", "b/other.yml", None),
        ("a/config.yml", "config.yml", None),
        ("src/x.c", "src/x.c", Some("src/x.c")),
        ("a/a/config.yml", "b/a/config.yml", Some("a/config.yml")),
        (
            "a/config.yml\t2026-09-01",
            "b/config.yml\t2026-09-01",
            Some("config.yml"),
        ),
        ("i/config.yml", "w/config.yml", Some("config.yml")),
        ("c/config.yml", "o/config.yml", Some("config.yml")),
    ] {
        cases.push((
            format!("--- {old}\n+++ {new}\n{hunk}"),
            target.map(|p| ("filesystem.write", p, 1)),
        ));
    }
    cases.push((
        "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+new\n".into(),
        Some(("filesystem.create", "new.txt", 1)),
    ));
    cases.push((
        "--- a/config.yml\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n".into(),
        Some(("filesystem.delete", "config.yml", 1)),
    ));
    for p in ["a/", "b/", "i/", "w/", "c/", "o/", ""] {
        for q in ["a/", "b/", "i/", "w/", "c/", "o/", ""] {
            cases.push((format!("diff --git {p}config.yml {q}config.yml\n--- {p}config.yml\n+++ {q}config.yml\n{hunk}"), Some(("filesystem.write", "config.yml", 1))));
        }
    }
    cases.extend([
        (format!("diff --git a/config.yml b/config.yml\n--- i/config.yml\n+++ w/config.yml\n{hunk}"), None),
        (format!("diff --git x/config.yml y/config.yml\n--- x/config.yml\n+++ y/config.yml\n{hunk}"), None),
        (format!("diff --git a/old.txt b/new.txt\n--- a/old.txt\n+++ b/new.txt\n{hunk}"), None),
        (format!("diff --git my file.txt my file.txt\n--- my file.txt\n+++ my file.txt\n{hunk}"), Some(("filesystem.write", "my file.txt", 1))),
        ("diff --git my file.txt my file.txt\nGIT binary patch\nliteral 1\nA00000\n".into(), None),
        ("diff --git a/dir b/bin/true b/dir b/bin/false\nGIT binary patch\nliteral 1\nA00000\n".into(), None),
        ("diff --git c/new.txt w/new.txt\nnew file mode 100644\n--- /dev/null\n+++ w/new.txt\n@@ -0,0 +1 @@\n+new\n".into(), Some(("filesystem.create", "new.txt", 1))),
        (format!("diff --git a/dir b/file b/dir b/file\n--- a/dir b/file\n+++ b/dir b/file\n{hunk}"), Some(("filesystem.write", "dir b/file", 1))),
    ]);
    for (text, expected) in cases {
        let plan = Engine::new()
            .analyze(&subject(
                ToolCall::FilePatch(FilePatchArgs {
                    format: PatchFormat::Unified,
                    text: text.clone(),
                }),
                Some("/work"),
            ))
            .unwrap();
        if let Some((operation, target, hunks)) = expected {
            assert_eq!(plan.effects.len(), 1, "{text}");
            let effect = &plan.effects[0];
            assert_eq!(effect.operation.0, operation, "{text}");
            assert_eq!(
                path(&effect.resource),
                Some(format!("/work/{target}").as_str()),
                "{text}"
            );
            assert_eq!(effect.attributes["hunks"], AttrValue::Int(hunks));
            if operation == "filesystem.write" {
                assert_eq!(effect.attributes["in_place"], AttrValue::Bool(true));
            }
            assert!(plan.boundaries.is_empty(), "{text}");
            assert_eq!(
                plan.coverage.0[&Domain::new("filesystem")].level,
                CoverageLevel::Full
            );
        } else {
            assert!(plan.effects.is_empty(), "{text}");
            assert_eq!(
                plan.boundaries[0].reason,
                BoundaryReason::PATCH_PARSE_FAILURE,
                "{text}"
            );
            assert_eq!(plan.boundaries[0].class, BoundaryClass::ParseFailure);
            assert_eq!(
                plan.coverage.0[&Domain::new("filesystem")].level,
                CoverageLevel::None
            );
        }
    }
}

#[test]
fn native_paths_keep_dollar_and_tilde_as_filename_bytes() {
    let engine = Engine::new();
    let context = HostContext {
        env: BTreeMap::from([(String::from("HOME"), String::from("/home/test"))]),
        ..Default::default()
    };
    let read = engine
        .analyze(&Subject::ToolCall {
            call: ToolCall::FileRead(FileReadArgs {
                path: "/repo/$literal".into(),
                range: None,
            }),
            cwd: Some("/work".into()),
            context: context.clone(),
        })
        .unwrap();
    assert_eq!(path(&read.effects[0].resource), Some("/repo/$literal"));
    assert!(
        !read
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );

    let tilde = engine
        .analyze(&Subject::ToolCall {
            call: ToolCall::FileRead(FileReadArgs {
                path: "~/$literal".into(),
                range: None,
            }),
            cwd: Some("/work".into()),
            context,
        })
        .unwrap();
    assert_eq!(path(&tilde.effects[0].resource), Some("/work/~/$literal"));

    let glob = engine
        .analyze(&subject(
            ToolCall::FsGlob(FsGlobArgs {
                pattern: "$HOME/*.rs".into(),
                root: None,
            }),
            Some("/work"),
        ))
        .unwrap();
    assert!(matches!(
        &glob.effects[0].resource,
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob }
        } if glob == "/work/$HOME/*.rs"
    ));
}
