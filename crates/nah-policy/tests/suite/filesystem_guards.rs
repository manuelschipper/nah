#![allow(clippy::disallowed_types)]

use crate::support;

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, HostIntegrityClass,
    PathScope, SemanticCode, Sensitivity,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::decision::Verdict;
use nah_proto::observation::ProjectGuardDeclaration;
use support::{context, guard_policy, guarded_stream, path};

fn unresolved_stream(
    invocation: EffectKind,
    operation: FilesystemOperation,
    recursive: bool,
) -> ActionStream {
    ActionStream::new(
        Coverage::Partial,
        vec![vec![
            invocation,
            EffectKind::FilesystemUnresolved {
                operation,
                recursive,
            },
        ]],
        vec![],
    )
    .unwrap()
}

fn host_integrity_stream(
    operation: FilesystemOperation,
    class: HostIntegrityClass,
) -> ActionStream {
    guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target: path("/reviewed/path"),
            scope: PathScope::System,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: Some(class),
            selects_root: false,
            selects_home: false,
            recursive: false,
            pattern: false,
        },
    })
}

fn project_effect(
    platform: Platform,
    root: &str,
    target: &str,
    operation: FilesystemOperation,
    recursive: bool,
    pattern: bool,
) -> EffectKind {
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target: AbsolutePath::new(platform, target).unwrap(),
            scope: PathScope::Project {
                root: AbsolutePath::new(platform, root).unwrap(),
            },
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: target == root,
            selects_home: false,
            recursive,
            pattern,
        },
    }
}

fn scoped_filesystem_effect(
    platform: Platform,
    target: &str,
    scope: PathScope,
    operation: FilesystemOperation,
    recursive: bool,
) -> EffectKind {
    EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation,
            target: AbsolutePath::new(platform, target).unwrap(),
            scope,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: false,
            recursive,
            pattern: false,
        },
    }
}

fn assert_project_root_block(stages: Vec<Vec<EffectKind>>, label: &str) {
    let stream = ActionStream::new(Coverage::Partial, stages, vec![]).unwrap();
    let decision = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &guard_policy("fs-project-root", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block, "{label}");
    assert_eq!(
        decision.policy_attributions()[0].name(),
        "fs-project-root",
        "{label}"
    );
}

#[test]
fn host_integrity_guards_are_independent_and_require_mutation() {
    for (guard, class) in [
        ("fs-shell-profile", HostIntegrityClass::ShellProfile),
        (
            "fs-startup-persistence",
            HostIntegrityClass::StartupPersistence,
        ),
        ("fs-auth-identity", HostIntegrityClass::AuthIdentity),
    ] {
        for operation in [FilesystemOperation::Write, FilesystemOperation::Delete] {
            let decision = nah_policy::decide(
                &host_integrity_stream(operation, class),
                &crate::support::evidence(
                    &host_integrity_stream(operation, class),
                    &nah_inline::InlineReport::default(),
                ),
                &guard_policy(guard, true),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict(), Verdict::Block, "{guard} {operation:?}");
            assert_eq!(decision.policy_attributions()[0].name(), guard);
        }
        let read = nah_policy::decide(
            &host_integrity_stream(FilesystemOperation::Read, class),
            &crate::support::evidence(
                &host_integrity_stream(FilesystemOperation::Read, class),
                &nah_inline::InlineReport::default(),
            ),
            &guard_policy(guard, true),
            &[],
        )
        .unwrap();
        assert_eq!(read.verdict(), Verdict::Delegate, "{guard} read");
    }

    let mismatched = nah_policy::decide(
        &host_integrity_stream(
            FilesystemOperation::Write,
            HostIntegrityClass::StartupPersistence,
        ),
        &crate::support::evidence(
            &host_integrity_stream(
                FilesystemOperation::Write,
                HostIntegrityClass::StartupPersistence,
            ),
            &nah_inline::InlineReport::default(),
        ),
        &guard_policy("fs-auth-identity", true),
        &[],
    )
    .unwrap();
    assert_eq!(mismatched.verdict(), Verdict::Delegate);
}

#[test]
fn startup_management_is_optional_and_independent_from_startup_paths() {
    let management = guarded_stream(EffectKind::SystemState {
        operation: SemanticCode::STARTUP_MANAGEMENT,
    });
    let enabled = nah_policy::decide(
        &management,
        &crate::support::evidence(&management, &nah_inline::InlineReport::default()),
        &guard_policy("fs-startup-management", true),
        &[],
    )
    .unwrap();
    assert_eq!(enabled.verdict(), Verdict::Block);
    assert_eq!(
        enabled.policy_attributions()[0].name(),
        "fs-startup-management"
    );
    assert!(enabled.reason().contains("nah tui"));

    let disabled = nah_policy::decide(
        &management,
        &crate::support::evidence(&management, &nah_inline::InlineReport::default()),
        &guard_policy("fs-startup-management", false),
        &[],
    )
    .unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);

    let path = host_integrity_stream(
        FilesystemOperation::Write,
        HostIntegrityClass::StartupPersistence,
    );
    assert_eq!(
        nah_policy::decide(
            &path,
            &crate::support::evidence(&path, &nah_inline::InlineReport::default()),
            &guard_policy("fs-startup-management", true),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
    assert_eq!(
        nah_policy::decide(
            &management,
            &crate::support::evidence(&management, &nah_inline::InlineReport::default()),
            &guard_policy("fs-startup-persistence", true),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
    assert_eq!(
        nah_policy::decide(
            &path,
            &crate::support::evidence(&path, &nah_inline::InlineReport::default()),
            &guard_policy("fs-startup-persistence", true),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );
}

#[test]
fn fs_system_tree_blocks_delete_or_recursive_permission_effects_selecting_root_and_system_trees() {
    for (operation, target, scope, recursive) in [
        (
            FilesystemOperation::Delete,
            "/",
            PathScope::OutsideProject,
            true,
        ),
        (FilesystemOperation::Delete, "/etc", PathScope::System, true),
        (
            FilesystemOperation::Delete,
            "/bin",
            PathScope::OutsideProject,
            true,
        ),
        (
            FilesystemOperation::Delete,
            "/usr/bin",
            PathScope::OutsideProject,
            true,
        ),
        (
            FilesystemOperation::Delete,
            "/usr/sbin",
            PathScope::OutsideProject,
            true,
        ),
        (
            FilesystemOperation::Delete,
            "/tmp",
            PathScope::OutsideProject,
            true,
        ),
        (
            FilesystemOperation::Delete,
            "/private/tmp",
            PathScope::OutsideProject,
            true,
        ),
        (
            FilesystemOperation::Delete,
            "/private/var",
            PathScope::System,
            true,
        ),
        (FilesystemOperation::Write, "/var", PathScope::System, true),
    ] {
        let invocation = if operation == FilesystemOperation::Write {
            EffectKind::known("chmod", "permission-weaken").unwrap()
        } else {
            EffectKind::opaque("bash").unwrap()
        };
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                invocation,
                EffectKind::Filesystem {
                    effect: FilesystemEffect {
                        operation,
                        target: path(target),
                        scope,
                        sensitivity: Sensitivity::None,
                        protection: None,
                        host_integrity: None,
                        selects_root: false,
                        selects_home: false,
                        recursive,
                        pattern: false,
                    },
                },
            ]],
            vec![],
        )
        .unwrap();
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("fs-system-tree", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{target}");
        assert_eq!(decision.policy_attributions()[0].name(), "fs-system-tree");
    }

    for target in [r"C:\", r"C:\Windows", r"D:\ProgramData"] {
        let stream = guarded_stream(EffectKind::Filesystem {
            effect: FilesystemEffect {
                operation: FilesystemOperation::Delete,
                target: AbsolutePath::new(Platform::Windows, target).unwrap(),
                scope: PathScope::System,
                sensitivity: Sensitivity::None,
                protection: None,
                host_integrity: None,
                selects_root: false,
                selects_home: false,
                recursive: true,
                pattern: false,
            },
        });
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy("fs-system-tree", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Block,
            "{target}"
        );
    }
}

#[test]
fn fs_home_blocks_delete_or_recursive_permission_effects_selecting_the_home_root() {
    let stream = guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Delete,
            target: path("/home/test"),
            scope: PathScope::Home,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: true,
            recursive: true,
            pattern: false,
        },
    });
    let decision = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &guard_policy("fs-home", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(decision.policy_attributions()[0].name(), "fs-home");

    let permission = ActionStream::new(
        Coverage::Partial,
        vec![vec![
            EffectKind::known("chmod", "permission-weaken").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Write,
                    target: path("/home/test"),
                    scope: PathScope::Home,
                    sensitivity: Sensitivity::None,
                    protection: None,
                    host_integrity: None,
                    selects_root: false,
                    selects_home: true,
                    recursive: true,
                    pattern: false,
                },
            },
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &permission,
            &crate::support::evidence(&permission, &nah_inline::InlineReport::default()),
            &guard_policy("fs-home", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );
}

#[test]
fn permission_weaken_is_optional_and_can_overlap_a_tree_guard() {
    let stream = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("chmod", "permission-weaken").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Write,
                    target: path("/etc"),
                    scope: PathScope::System,
                    sensitivity: Sensitivity::None,
                    protection: None,
                    host_integrity: None,
                    selects_root: false,
                    selects_home: false,
                    recursive: true,
                    pattern: false,
                },
            },
        ]],
        vec![],
    )
    .unwrap();
    let policy = context(
        &[("fs-permission-weaken", true), ("fs-system-tree", true)],
        vec![],
        ProjectGuardDeclaration::Absent,
    )
    .1;
    let decision = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &policy,
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(
        decision
            .policy_attributions()
            .iter()
            .map(|attribution| attribution.name())
            .collect::<Vec<_>>(),
        ["fs-permission-weaken", "fs-system-tree"]
    );

    assert_eq!(
        nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("fs-permission-weaken", false),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
    let ordinary = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("chmod", "permission-change").unwrap(),
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &ordinary,
            &crate::support::evidence(&ordinary, &nah_inline::InlineReport::default()),
            &guard_policy("fs-permission-weaken", true),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn fs_outside_workspace_delete_blocks_only_concrete_recursive_deletes_outside_project() {
    for (target, scope) in [
        ("/home/test/Downloads/old-build", PathScope::Home),
        ("/etc/old-config", PathScope::System),
        ("/srv/data", PathScope::OutsideProject),
    ] {
        let stream = guarded_stream(scoped_filesystem_effect(
            Platform::Linux,
            target,
            scope,
            FilesystemOperation::Delete,
            true,
        ));
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("fs-outside-workspace-delete", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{target}");
        assert_eq!(
            decision.policy_attributions()[0].name(),
            "fs-outside-workspace-delete"
        );
    }

    for effect in [
        project_effect(
            Platform::Linux,
            "/repo",
            "/repo/build",
            FilesystemOperation::Delete,
            true,
            false,
        ),
        scoped_filesystem_effect(
            Platform::Linux,
            "/srv/data",
            PathScope::OutsideProject,
            FilesystemOperation::Delete,
            false,
        ),
        scoped_filesystem_effect(
            Platform::Linux,
            "/srv/data",
            PathScope::OutsideProject,
            FilesystemOperation::Write,
            true,
        ),
    ] {
        let decision = nah_policy::decide(
            &guarded_stream(effect.clone()),
            &crate::support::evidence(
                &guarded_stream(effect),
                &nah_inline::InlineReport::default(),
            ),
            &guard_policy("fs-outside-workspace-delete", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
        assert!(decision.policy_attributions().is_empty());
    }

    let unresolved = unresolved_stream(
        EffectKind::known("rm", "delete").unwrap(),
        FilesystemOperation::Delete,
        true,
    );
    assert_eq!(
        nah_policy::decide(
            &unresolved,
            &crate::support::evidence(&unresolved, &nah_inline::InlineReport::default()),
            &guard_policy("fs-outside-workspace-delete", true),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn fs_outside_workspace_delete_excludes_only_reviewed_temporary_roots() {
    for (platform, target) in [
        (Platform::Linux, "/tmp"),
        (Platform::Linux, "/tmp/old-build"),
        (Platform::Macos, "/private/tmp"),
        (Platform::Macos, "/private/tmp/old-build"),
        (Platform::Linux, "/var/tmp"),
        (Platform::Linux, "/var/tmp/old-build"),
        (Platform::Windows, r"C:\Users\test\AppData\Local\Temp"),
        (
            Platform::Windows,
            r"c:\Users\test\APPDATA\local\TEMP\old-build",
        ),
        (Platform::Windows, r"C:\Windows\Temp"),
        (Platform::Windows, "d:/WINDOWS/TEMP/old-build"),
    ] {
        let stream = guarded_stream(scoped_filesystem_effect(
            platform,
            target,
            PathScope::OutsideProject,
            FilesystemOperation::Delete,
            true,
        ));
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy("fs-outside-workspace-delete", true),
                &[],
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{target}"
        );
    }

    for (platform, target) in [
        (Platform::Linux, "/tmp-old"),
        (Platform::Linux, "/private/tmp-old"),
        (Platform::Linux, "/var/tmp-old"),
        (Platform::Windows, r"C:\Users\test\AppData\Local\Temp-old"),
        (Platform::Windows, r"C:\Windows\Temp-old"),
    ] {
        let stream = guarded_stream(scoped_filesystem_effect(
            platform,
            target,
            PathScope::OutsideProject,
            FilesystemOperation::Delete,
            true,
        ));
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy("fs-outside-workspace-delete", true),
                &[],
            )
            .unwrap()
            .verdict(),
            Verdict::Block,
            "{target}"
        );
    }
}

#[test]
fn fs_outside_workspace_delete_preserves_home_and_system_guard_attribution() {
    let policy = context(
        &[
            ("fs-system-tree", true),
            ("fs-home", true),
            ("fs-outside-workspace-delete", true),
        ],
        vec![],
        ProjectGuardDeclaration::Absent,
    )
    .1;
    for (target, scope, selects_home, expected) in [
        (
            "/etc",
            PathScope::System,
            false,
            ["fs-system-tree", "fs-outside-workspace-delete"],
        ),
        (
            "/home/test",
            PathScope::Home,
            true,
            ["fs-home", "fs-outside-workspace-delete"],
        ),
    ] {
        let stream = guarded_stream(EffectKind::Filesystem {
            effect: FilesystemEffect {
                operation: FilesystemOperation::Delete,
                target: path(target),
                scope,
                sensitivity: Sensitivity::None,
                protection: None,
                host_integrity: None,
                selects_root: false,
                selects_home,
                recursive: true,
                pattern: false,
            },
        });
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &policy,
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block);
        assert_eq!(decision.policy_attributions().len(), expected.len());
        for guard in expected {
            assert!(
                decision
                    .policy_attributions()
                    .iter()
                    .any(|attribution| attribution.name() == guard),
                "{guard}"
            );
        }
    }
}

#[test]
fn fs_project_root_blocks_recursive_deletes_of_exact_roots_and_root_wide_patterns() {
    for (platform, root, separator) in [
        (Platform::Linux, "/repo", "/"),
        (Platform::Windows, "C:/repo", "/"),
        (Platform::Windows, r"C:\repo", r"\"),
    ] {
        assert_project_root_block(
            vec![vec![
                EffectKind::known("rm", "remove").unwrap(),
                project_effect(
                    platform,
                    root,
                    root,
                    FilesystemOperation::Delete,
                    true,
                    false,
                ),
            ]],
            root,
        );
        for suffix in ["*", ".*", "{*,.*}"] {
            let target = format!("{root}{separator}{suffix}");
            assert_project_root_block(
                vec![vec![
                    EffectKind::known("rm", "remove").unwrap(),
                    project_effect(
                        platform,
                        root,
                        &target,
                        FilesystemOperation::Delete,
                        true,
                        true,
                    ),
                ]],
                &target,
            );
        }
    }
}

#[test]
fn fs_project_root_blocks_same_stage_recursive_permission_changes_for_every_known_tool() {
    for (tool, operation) in [
        ("chmod", "permission-weaken"),
        ("chmod", "permission-change"),
        ("chown", "permission-change"),
        ("chgrp", "permission-change"),
        ("setfacl", "permission-change"),
    ] {
        assert_project_root_block(
            vec![vec![
                EffectKind::known(tool, operation).unwrap(),
                project_effect(
                    Platform::Linux,
                    "/repo",
                    "/repo",
                    FilesystemOperation::Write,
                    true,
                    false,
                ),
            ]],
            tool,
        );
    }
}

#[test]
fn fs_project_root_delegates_below_its_exact_scope_operation_and_stage_boundary() {
    let controls = [
        vec![vec![
            EffectKind::known("rm", "remove").unwrap(),
            project_effect(
                Platform::Linux,
                "/repo",
                "/repo/build",
                FilesystemOperation::Delete,
                true,
                false,
            ),
        ]],
        vec![vec![
            EffectKind::known("rm", "remove").unwrap(),
            project_effect(
                Platform::Linux,
                "/repo",
                "/repo/src/*",
                FilesystemOperation::Delete,
                true,
                true,
            ),
        ]],
        vec![vec![
            EffectKind::known("rm", "remove").unwrap(),
            project_effect(
                Platform::Linux,
                "/repo",
                "/repo/**",
                FilesystemOperation::Delete,
                true,
                true,
            ),
        ]],
        vec![vec![
            EffectKind::known("cp", "recursive-copy").unwrap(),
            project_effect(
                Platform::Linux,
                "/repo",
                "/repo",
                FilesystemOperation::Write,
                true,
                false,
            ),
        ]],
        vec![vec![
            EffectKind::opaque("chattr").unwrap(),
            project_effect(
                Platform::Linux,
                "/repo",
                "/repo",
                FilesystemOperation::Write,
                true,
                false,
            ),
        ]],
        vec![
            vec![EffectKind::known("chmod", "permission-change").unwrap()],
            vec![
                EffectKind::opaque("writer").unwrap(),
                project_effect(
                    Platform::Linux,
                    "/repo",
                    "/repo",
                    FilesystemOperation::Write,
                    true,
                    false,
                ),
            ],
        ],
        vec![vec![
            EffectKind::known("rm", "remove").unwrap(),
            project_effect(
                Platform::Linux,
                "/repo",
                "/repo",
                FilesystemOperation::Delete,
                false,
                false,
            ),
        ]],
        vec![vec![
            EffectKind::known("rm", "remove").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Delete,
                    target: path("/outside"),
                    scope: PathScope::OutsideProject,
                    sensitivity: Sensitivity::None,
                    protection: None,
                    host_integrity: None,
                    selects_root: false,
                    selects_home: false,
                    recursive: true,
                    pattern: false,
                },
            },
        ]],
        vec![vec![
            EffectKind::known("rm", "remove").unwrap(),
            EffectKind::FilesystemUnresolved {
                operation: FilesystemOperation::Delete,
                recursive: true,
            },
        ]],
    ];

    for control in controls {
        let stream = ActionStream::new(Coverage::Partial, control, vec![]).unwrap();
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("fs-project-root", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate, "{stream:?}");
        assert!(decision.policy_attributions().is_empty(), "{stream:?}");
    }
}

#[test]
fn unbounded_destructive_tree_effects_select_both_root_and_home_guards() {
    for guard in ["fs-system-tree", "fs-home"] {
        for stream in [
            unresolved_stream(
                EffectKind::known("rm", "delete").unwrap(),
                FilesystemOperation::Delete,
                true,
            ),
            unresolved_stream(
                EffectKind::known("chmod", "permission-change").unwrap(),
                FilesystemOperation::Write,
                true,
            ),
            unresolved_stream(
                EffectKind::known("chmod", "permission-weaken").unwrap(),
                FilesystemOperation::Write,
                true,
            ),
        ] {
            let decision = nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict(), Verdict::Block, "{guard}");
            assert_eq!(decision.policy_attributions()[0].name(), guard);
        }
    }
}

#[test]
fn unbounded_filesystem_effects_fail_closed_only_at_the_tree_destruction_boundary() {
    for stream in [
        unresolved_stream(
            EffectKind::known("cat", "read").unwrap(),
            FilesystemOperation::Read,
            true,
        ),
        unresolved_stream(
            EffectKind::known("rm", "delete").unwrap(),
            FilesystemOperation::Delete,
            false,
        ),
        unresolved_stream(
            EffectKind::known("cp", "recursive-copy").unwrap(),
            FilesystemOperation::Write,
            true,
        ),
        unresolved_stream(
            EffectKind::known("chmod", "permission-change").unwrap(),
            FilesystemOperation::Write,
            false,
        ),
    ] {
        for guard in ["fs-system-tree", "fs-home"] {
            assert_eq!(
                nah_policy::decide(
                    &stream,
                    &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                    &guard_policy(guard, true),
                    &[]
                )
                .unwrap()
                .verdict(),
                Verdict::Delegate,
                "{guard}"
            );
        }
    }
}

#[test]
fn file_only_delete_effects_do_not_claim_directory_tree_destruction() {
    for (guard, target, scope, selects_home) in [
        ("fs-system-tree", "/etc", PathScope::System, false),
        ("fs-home", "/home/test", PathScope::Home, true),
    ] {
        let stream = guarded_stream(EffectKind::Filesystem {
            effect: FilesystemEffect {
                operation: FilesystemOperation::Delete,
                target: path(target),
                scope,
                sensitivity: Sensitivity::None,
                protection: None,
                host_integrity: None,
                selects_root: false,
                selects_home,
                recursive: false,
                pattern: false,
            },
        });
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}: {target}"
        );
    }
}

#[test]
fn fs_system_tree_blocks_only_same_stage_known_root_relocation() {
    let root_pattern = || EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Delete,
            target: path("/*"),
            scope: PathScope::OutsideProject,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: false,
            recursive: false,
            pattern: true,
        },
    };
    for program in ["mv", "/usr/bin/mv", "wipe"] {
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::known(program, "move").unwrap(),
                root_pattern(),
            ]],
            vec![],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy("fs-system-tree", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Block,
            "{program}"
        );
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy("fs-home", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{program}"
        );
    }

    let controls = [
        ActionStream::new(
            Coverage::Partial,
            vec![vec![EffectKind::opaque("mv").unwrap(), root_pattern()]],
            vec![],
        )
        .unwrap(),
        ActionStream::new(
            Coverage::Partial,
            vec![
                vec![EffectKind::known("mv", "move").unwrap()],
                vec![EffectKind::opaque("bash").unwrap(), root_pattern()],
            ],
            vec![],
        )
        .unwrap(),
        ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::known("mv", "copy").unwrap(),
                root_pattern(),
            ]],
            vec![],
        )
        .unwrap(),
        ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::known("mv", "move").unwrap(),
                EffectKind::Filesystem {
                    effect: FilesystemEffect {
                        pattern: false,
                        ..match root_pattern() {
                            EffectKind::Filesystem { effect } => effect,
                            _ => unreachable!(),
                        }
                    },
                },
            ]],
            vec![],
        )
        .unwrap(),
    ];
    for control in controls {
        assert_eq!(
            nah_policy::decide(
                &control,
                &crate::support::evidence(&control, &nah_inline::InlineReport::default()),
                &guard_policy("fs-system-tree", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{control:?}"
        );
    }
}

#[test]
fn fs_raw_device_blocks_visible_writes_to_raw_storage_and_the_sysrq_trigger() {
    for target in [
        "/dev/sda",
        "/dev/sdaa",
        "/dev/nvme0n1",
        "/dev/nvme0c0n1",
        "/dev/pmem0",
        "/dev/pmem0s",
        "/dev/dax0.0",
        "/dev/loop0p1",
        "/dev/md0p1",
        "/dev/ada0p1",
        "/dev/nda0",
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
        "/dev/loop0",
        "/proc/sysrq-trigger",
    ] {
        let stream = guarded_stream(EffectKind::Filesystem {
            effect: FilesystemEffect {
                operation: FilesystemOperation::Write,
                target: path(target),
                scope: PathScope::System,
                sensitivity: Sensitivity::None,
                protection: None,
                host_integrity: None,
                selects_root: false,
                selects_home: false,
                recursive: false,
                pattern: false,
            },
        });
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("fs-raw-device", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{target}");
        assert_eq!(decision.policy_attributions()[0].name(), "fs-raw-device");
    }
}

#[test]
fn fs_forkbomb_blocks_positive_shell_fork_bomb_evidence() {
    let stream = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::FORK_BOMB,
    });
    let decision = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &guard_policy("fs-forkbomb", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(decision.policy_attributions()[0].name(), "fs-forkbomb");
}

#[test]
fn fs_volume_destroy_blocks_only_typed_logical_destruction() {
    let destructive = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::LOGICAL_STORAGE_DESTROY,
    });
    let decision = nah_policy::decide(
        &destructive,
        &crate::support::evidence(&destructive, &nah_inline::InlineReport::default()),
        &guard_policy("fs-volume-destroy", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(
        decision.policy_attributions()[0].name(),
        "fs-volume-destroy"
    );

    let inspect = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::new("storage-inspect").unwrap(),
    });
    assert_eq!(
        nah_policy::decide(
            &inspect,
            &crate::support::evidence(&inspect, &nah_inline::InlineReport::default()),
            &guard_policy("fs-volume-destroy", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn filesystem_guards_do_not_fire_when_disabled_or_below_their_boundary() {
    let home_child = guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Delete,
            target: path("/home/test/Downloads/old"),
            scope: PathScope::Home,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: false,
            recursive: true,
            pattern: false,
        },
    });
    assert_eq!(
        nah_policy::decide(
            &home_child,
            &crate::support::evidence(&home_child, &nah_inline::InlineReport::default()),
            &guard_policy("fs-home", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );

    let root = guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Delete,
            target: path("/"),
            scope: PathScope::OutsideProject,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: false,
            recursive: true,
            pattern: false,
        },
    });
    assert_eq!(
        nah_policy::decide(
            &root,
            &crate::support::evidence(&root, &nah_inline::InlineReport::default()),
            &guard_policy("fs-system-tree", false),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );

    for target in [
        "/bin/tool",
        "/usr/bin/old-tool",
        "/usr/sbin/old-tool",
        "/tmp/old-build",
        "/private/tmp/old-build",
    ] {
        let child = guarded_stream(EffectKind::Filesystem {
            effect: FilesystemEffect {
                operation: FilesystemOperation::Delete,
                target: path(target),
                scope: PathScope::OutsideProject,
                sensitivity: Sensitivity::None,
                protection: None,
                host_integrity: None,
                selects_root: false,
                selects_home: false,
                recursive: true,
                pattern: false,
            },
        });
        assert_eq!(
            nah_policy::decide(
                &child,
                &crate::support::evidence(&child, &nah_inline::InlineReport::default()),
                &guard_policy("fs-system-tree", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{target}"
        );
    }

    let windows_child = guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Delete,
            target: AbsolutePath::new(Platform::Windows, r"C:\Windows\Temp\old-build").unwrap(),
            scope: PathScope::System,
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root: false,
            selects_home: false,
            recursive: true,
            pattern: false,
        },
    });
    assert_eq!(
        nah_policy::decide(
            &windows_child,
            &crate::support::evidence(&windows_child, &nah_inline::InlineReport::default()),
            &guard_policy("fs-system-tree", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );

    for target in [
        "/dev/null",
        "/dev/nvmefoo1",
        "/dev/sd",
        "/dev/pmem",
        "/tmp/disk.img",
    ] {
        let ordinary = guarded_stream(EffectKind::Filesystem {
            effect: FilesystemEffect {
                operation: FilesystemOperation::Write,
                target: path(target),
                scope: PathScope::OutsideProject,
                sensitivity: Sensitivity::None,
                protection: None,
                host_integrity: None,
                selects_root: false,
                selects_home: false,
                recursive: false,
                pattern: false,
            },
        });
        assert_eq!(
            nah_policy::decide(
                &ordinary,
                &crate::support::evidence(&ordinary, &nah_inline::InlineReport::default()),
                &guard_policy("fs-raw-device", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{target}"
        );
    }
}

// An alternate producer must not bypass an owned guard, or turn absent,
// conditional, conservative, or foreign-host evidence into a proven match.
#[test]
fn shared_filesystem_facts_preserve_each_guard_and_evidence_boundary() {
    use Knowledge::{Known, Unknown};
    use nah_proto::effects::*;
    let public = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
    let base = support::evidence(&public, &nah_inline::InlineReport::default());
    for name in [
        "fs-auth-identity",
        "fs-forkbomb",
        "fs-home",
        "fs-outside-workspace-delete",
        "fs-permission-weaken",
        "fs-project-root",
        "fs-raw-device",
        "fs-shell-profile",
        "fs-startup-management",
        "fs-startup-persistence",
        "fs-system-tree",
        "fs-volume-destroy",
    ] {
        let mut graph = base.graph().clone();
        let path = path(match name {
            "fs-raw-device" => "/dev/sda",
            "fs-system-tree" => "/etc",
            "fs-home" => "/home/test",
            "fs-project-root" => "/repo",
            _ => "/outside",
        });
        let target = ResourceId(0);
        let labels = ResourceLabels {
            lexical: Known(path),
            canonical: Unknown,
            scope: Known(match name {
                "fs-home" => PathScope::Home,
                "fs-project-root" => PathScope::Project {
                    root: support::path("/repo"),
                },
                "fs-system-tree" | "fs-raw-device" => PathScope::System,
                _ => PathScope::OutsideProject,
            }),
            sensitivity: Unknown,
            protection: Unknown,
            host_integrity: Known(vec![
                HostIntegrityClass::AuthIdentity,
                HostIntegrityClass::ShellProfile,
                HostIntegrityClass::StartupPersistence,
            ]),
            selects_home: if name == "fs-home" {
                Reach::Yes
            } else {
                Reach::No
            },
            selects_project: if name == "fs-project-root" {
                Reach::Yes
            } else {
                Reach::No
            },
            selects_root: Reach::Unknown,
            is_symlink: Unknown,
            link_target: Unknown,
            descendants_complete: Unknown,
            reach: vec![],
        };
        let mut resource = EffectResource {
            id: target,
            realm: Realm::Host,
            identity: ResourceIdentity {
                kind: ResourceKind::HostPath,
                details: Unknown,
                provider: Unknown,
                name: Unknown,
            },
            selection: Selection::Exact,
            labels: Some(labels),
        };
        let payload = match name {
            "fs-forkbomb" => FactPayload::ProcessGrowth {
                background: Unknown,
                repetition: Unknown,
                launch_cycle: Unknown,
                wait: Unknown,
                dominator: Unknown,
                growth: Bound::Unknown,
                abstract_unbounded_spawn: Known(true),
            },
            "fs-startup-management" => {
                resource.identity.kind = ResourceKind::HostSystem;
                resource.labels = None;
                FactPayload::SystemChange {
                    target,
                    operation: SystemOperation::StartupChange,
                    selection: Selection::Unknown,
                    runtime_only: Known(false),
                    persistent: Known(true),
                    active: Known(true),
                    cancel: Known(false),
                    help: Known(false),
                }
            }
            "fs-volume-destroy" => {
                resource.identity.kind = ResourceKind::LiveVolume;
                resource.labels = None;
                FactPayload::StorageChange {
                    target,
                    destination: None,
                    operation: StorageOperation::Destroy,
                    kind: StorageTarget::LiveVolume,
                    selection: Selection::Unknown,
                    recursive: Unknown,
                    destination_deletion: Unknown,
                    allow_remove_all: nah_proto::effects::Knowledge::Unknown,
                    all_selection_requested: nah_proto::effects::Knowledge::Unknown,
                }
            }
            _ => FactPayload::FilesystemAccess {
                target,
                destination: None,
                operation: match name {
                    "fs-permission-weaken" => FilesystemOperation::PermissionChange,
                    "fs-raw-device" => FilesystemOperation::Write,
                    _ => FilesystemOperation::Delete,
                },
                recursive: Known(true),
                truncate: Unknown,
                permissions: PermissionGrants {
                    world_write: Known(true),
                    setuid: Unknown,
                    setgid: Unknown,
                },
                purpose: AccessPurpose::Unknown,
            },
        };
        graph.resources.push(resource);
        graph.facts.push(EffectFact {
            id: FactId(0),
            call: CallId(0),
            realm: Realm::Host,
            certainty: Certainty::Exact,
            modality: Modality::May,
            condition: None,
            occurrences: None,
            payload,
        });
        let evidence = GuardEvidence::new(graph.clone(), base.public_selection().clone()).unwrap();
        let enabled = guard_policy(name, true);
        let expected = nah_policy::decide(&public, &evidence, &enabled, &[]).unwrap();
        assert_eq!(
            expected
                .policy_attributions()
                .iter()
                .map(|guard| guard.name())
                .collect::<Vec<_>>(),
            [name],
            "{name}"
        );
        assert_eq!(
            nah_policy::decide(&public, &evidence, &guard_policy(name, false), &[])
                .unwrap()
                .verdict(),
            Verdict::Delegate,
            "{name}"
        );
        // Producer identity and invocation shape are not policy inputs.
        for kind in [
            InvocationKind::Native,
            InvocationKind::VisibleCode,
            InvocationKind::Shell,
            InvocationKind::Argv,
        ] {
            let mut alternate = graph.clone();
            alternate.calls[0].kind = kind;
            alternate.calls[0].identity = Known("alternate-producer".into());
            let alternate = GuardEvidence::new(alternate, base.public_selection().clone()).unwrap();
            assert_eq!(
                nah_policy::decide(&public, &alternate, &enabled, &[]).unwrap(),
                expected,
                "{name}"
            );
        }
        for boundary in ["absent", "conditional", "conservative", "remote", "unknown"] {
            let mut abstaining = graph.clone();
            match boundary {
                "absent" => abstaining.facts.clear(),
                "conditional" => {
                    abstaining.conditions.push(EffectCondition {
                        id: ConditionId(0),
                        complete: false,
                        expression: ConditionExpr::Literal { atom: 0 },
                        alternative_group: None,
                    });
                    abstaining.facts[0].condition = Some(ConditionUse {
                        id: ConditionId(0),
                        positive: true,
                    });
                }
                "conservative" => abstaining.facts[0].certainty = Certainty::Conservative,
                "remote" => {
                    abstaining.facts[0].realm = Realm::Remote { identity: Unknown };
                    for resource in &mut abstaining.resources {
                        resource.realm = Realm::Remote { identity: Unknown };
                        resource.labels = None;
                    }
                }
                _ => match &mut abstaining.facts[0].payload {
                    FactPayload::ProcessGrowth {
                        abstract_unbounded_spawn,
                        ..
                    } => *abstract_unbounded_spawn = Unknown,
                    FactPayload::SystemChange { persistent, .. } => *persistent = Unknown,
                    FactPayload::StorageChange { kind, .. } => *kind = StorageTarget::Snapshot,
                    FactPayload::FilesystemAccess {
                        operation,
                        permissions,
                        ..
                    } => {
                        if name == "fs-permission-weaken" {
                            permissions.world_write = Unknown;
                        } else {
                            *operation = FilesystemOperation::Read;
                        }
                    }
                    _ => unreachable!(),
                },
            }
            let abstaining =
                GuardEvidence::new(abstaining, base.public_selection().clone()).unwrap();
            let decision = nah_policy::decide(&public, &abstaining, &enabled, &[]).unwrap();
            assert_eq!(decision.verdict(), Verdict::Delegate, "{name}: {boundary}");
            assert!(decision.policy_attributions().is_empty());
        }
    }
}
