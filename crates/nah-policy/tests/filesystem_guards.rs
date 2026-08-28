#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, HostIntegrityClass,
    PathScope, Sensitivity,
};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream, path};

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

fn assert_project_root_block(stages: Vec<Vec<EffectKind>>, label: &str) {
    let stream = ActionStream::new(Coverage::Partial, stages, vec![]).unwrap();
    let decision =
        nah_policy::decide(&stream, &guard_policy("fs-project-root", true), &[]).unwrap();
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
                &guard_policy(guard, true),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict(), Verdict::Block, "{guard} {operation:?}");
            assert_eq!(decision.policy_attributions()[0].name(), guard);
            assert!(decision.reason().contains("nah tui"));
        }
        let read = nah_policy::decide(
            &host_integrity_stream(FilesystemOperation::Read, class),
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
        &guard_policy("fs-auth-identity", true),
        &[],
    )
    .unwrap();
    assert_eq!(mismatched.verdict(), Verdict::Delegate);
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
            EffectKind::known("chmod", "permission-change").unwrap()
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
        let decision =
            nah_policy::decide(&stream, &guard_policy("fs-system-tree", true), &[]).unwrap();
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
            nah_policy::decide(&stream, &guard_policy("fs-system-tree", true), &[])
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
    let decision = nah_policy::decide(&stream, &guard_policy("fs-home", true), &[]).unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(decision.policy_attributions()[0].name(), "fs-home");
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
    for tool in ["chmod", "chown", "chgrp", "setfacl"] {
        assert_project_root_block(
            vec![vec![
                EffectKind::known(tool, "permission-change").unwrap(),
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
        let decision =
            nah_policy::decide(&stream, &guard_policy("fs-project-root", true), &[]).unwrap();
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
        ] {
            let decision = nah_policy::decide(&stream, &guard_policy(guard, true), &[]).unwrap();
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
                nah_policy::decide(&stream, &guard_policy(guard, true), &[])
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
            nah_policy::decide(&stream, &guard_policy(guard, true), &[])
                .unwrap()
                .verdict(),
            Verdict::Delegate,
            "{guard}: {target}"
        );
    }
}

#[test]
fn fs_root_blocks_only_same_stage_known_root_relocation() {
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
            nah_policy::decide(&stream, &guard_policy("fs-system-tree", true), &[])
                .unwrap()
                .verdict(),
            Verdict::Block,
            "{program}"
        );
        assert_eq!(
            nah_policy::decide(&stream, &guard_policy("fs-home", true), &[])
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
            nah_policy::decide(&control, &guard_policy("fs-system-tree", true), &[])
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
        let decision =
            nah_policy::decide(&stream, &guard_policy("fs-raw-device", true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{target}");
        assert_eq!(decision.policy_attributions()[0].name(), "fs-raw-device");
    }
    let windows = guarded_stream(EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Write,
            target: AbsolutePath::new(Platform::Windows, r"\\.\PhysicalDrive0").unwrap(),
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
    assert_eq!(
        nah_policy::decide(&windows, &guard_policy("fs-raw-device", true), &[])
            .unwrap()
            .verdict(),
        Verdict::Block
    );
}

#[test]
fn fs_forkbomb_blocks_positive_shell_fork_bomb_evidence() {
    let stream = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::FORK_BOMB,
    });
    let decision = nah_policy::decide(&stream, &guard_policy("fs-forkbomb", true), &[]).unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(decision.policy_attributions()[0].name(), "fs-forkbomb");
}

#[test]
fn fs_storage_destroy_blocks_only_typed_logical_destruction() {
    let destructive = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::LOGICAL_STORAGE_DESTROY,
    });
    let decision =
        nah_policy::decide(&destructive, &guard_policy("fs-storage-destroy", true), &[]).unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(
        decision.policy_attributions()[0].name(),
        "fs-storage-destroy"
    );

    let inspect = guarded_stream(EffectKind::SystemState {
        operation: nah_proto::action::SemanticCode::new("storage-inspect").unwrap(),
    });
    assert_eq!(
        nah_policy::decide(&inspect, &guard_policy("fs-storage-destroy", true), &[])
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
        nah_policy::decide(&home_child, &guard_policy("fs-home", true), &[])
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
        nah_policy::decide(&root, &guard_policy("fs-system-tree", false), &[])
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
            nah_policy::decide(&child, &guard_policy("fs-system-tree", true), &[])
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
        nah_policy::decide(&windows_child, &guard_policy("fs-system-tree", true), &[])
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
            nah_policy::decide(&ordinary, &guard_policy("fs-raw-device", true), &[])
                .unwrap()
                .verdict(),
            Verdict::Delegate,
            "{target}"
        );
    }
}
