//! Destructive storage/device commands — the disasters nah blocks on.

use effinterp_engine::Engine;
use effinterp_proto::{AttrValue, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

fn exec(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn has_effect_on(plan: &Plan, op: &str, contains: &str) -> bool {
    plan.effects.iter().any(|e| {
        e.operation.0 == op
            && match &e.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => path.contains(contains),
                _ => false,
            }
    })
}

fn attr(plan: &Plan, op: &str, key: &str) -> bool {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op)
        .and_then(|e| e.attributes.get(key))
        .map(|v| *v == AttrValue::Bool(true))
        .unwrap_or(false)
}

#[test]
fn dd_of_device_writes_raw_device() {
    let plan = exec(&["dd", "if=/dev/zero", "of=/dev/sda"]);
    assert!(has_effect_on(&plan, "filesystem.write", "sda"));
    assert!(has_effect_on(&plan, "filesystem.read", "zero"));
    assert!(attr(&plan, "filesystem.write", "raw_device"));
}

#[test]
fn dd_preserves_pattern_and_symbolic_output_targets() {
    for (source, resource, raw_device) in [
        (
            "dd if=/dev/zero of=/dev/sd?",
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: "/dev/sd?".into(),
                    narrowing: Default::default(),
                },
            },
            true,
        ),
        (
            "dd if=x of=$DEV",
            ResourceExpr::Environment { name: "DEV".into() },
            false,
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let write = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.write")
            .unwrap();
        assert_eq!(write.resource, resource);
        assert_eq!(
            write.attributes.get("truncate"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(
            write.attributes.get("raw_device"),
            raw_device.then_some(&AttrValue::Bool(true))
        );
        assert!(has_effect_on(
            &plan,
            "filesystem.read",
            if raw_device { "/dev/zero" } else { "/w/x" }
        ));
    }
}

#[test]
fn mkfs_formats_the_device() {
    let plan = exec(&["mkfs.ext4", "/dev/sdb"]);
    assert!(has_effect_on(&plan, "filesystem.write", "sdb"));
    assert!(attr(&plan, "filesystem.write", "format"));
    for argv in [
        vec!["mkfs.ext4", "-n", "/dev/sda"],
        vec!["mke2fs", "-Fn", "/dev/sda"],
    ] {
        let preview = exec(&argv);
        assert!(!has_effect_on(&preview, "filesystem.write", "/dev/sda"));
        assert!(
            !preview
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "system.storage_destroy")
        );
    }
    for argv in [
        vec!["mkfs.ext4", "-L", "-n", "/dev/sda"],
        vec!["mkfs.ext4", "--", "-n", "/dev/sda"],
        vec!["mkfs.vfat", "-n", "LABEL", "/dev/sda"],
    ] {
        assert!(
            has_effect_on(&exec(&argv), "filesystem.write", "/dev/sda"),
            "{argv:?}"
        );
    }
}

#[test]
fn wipefs_writes_the_device() {
    let plan = exec(&["wipefs", "-a", "/dev/sdc"]);
    assert!(has_effect_on(&plan, "filesystem.write", "sdc"));
    let offset = exec(&["wipefs", "-o", "0x438", "/dev/sdc"]);
    assert!(has_effect_on(&offset, "filesystem.write", "sdc"));
    assert!(!has_effect_on(&offset, "filesystem.write", "0x438"));
    for argv in [
        vec!["wipefs", "/dev/sdc"],
        vec!["wipefs", "-a", "--no-act", "/dev/sdc"],
        vec!["wipefs", "-na", "/dev/sdc"],
    ] {
        let inspection = exec(&argv);
        assert!(has_effect_on(&inspection, "filesystem.read", "sdc"));
        assert!(!has_effect_on(&inspection, "filesystem.write", "sdc"));
        assert!(
            !inspection
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "system.storage_destroy")
        );
    }
}

#[test]
fn shred_overwrites_and_removes() {
    let plan = exec(&["shred", "-u", "/secret/key"]);
    assert!(has_effect_on(&plan, "filesystem.write", "key"));
    assert!(has_effect_on(&plan, "filesystem.delete", "key"));
    // Option values are not files to overwrite; the random source is read.
    let plan = exec(&[
        "shred",
        "-n",
        "1",
        "--size=1M",
        "--random-source",
        "/dev/urandom",
        "-z",
        "/dev/sdb",
    ]);
    let writes = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.write")
        .map(|e| effinterp_proto::display_resource(&e.resource))
        .collect::<Vec<_>>();
    assert_eq!(writes, ["fs:/dev/sdb"]);
    assert!(has_effect_on(&plan, "filesystem.read", "/dev/urandom"));
}

#[test]
fn lvremove_deletes_the_volume() {
    let plan = exec(&["lvremove", "/dev/vg/lv"]);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "system.storage_destroy"
                && effinterp_proto::display_resource(&e.resource) == "vol:lvm//dev/vg/lv")
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete")
    );
}

#[test]
fn lvm_wrapper_dispatches_to_remove() {
    let plan = exec(&["lvm", "vgremove", "/dev/archive"]);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "system.storage_destroy"
                && effinterp_proto::display_resource(&e.resource) == "vol:lvm//dev/archive")
    );
}

#[test]
fn lvm_options_do_not_become_destroy_targets_or_execution_modes() {
    for command in ["lvremove", "vgremove", "pvremove"] {
        for option in ["-h", "--help", "--longhelp", "--version"] {
            for argv in [
                vec![command, option, "vg/data"],
                vec!["lvm", option, command, "vg/data"],
            ] {
                let plan = exec(&argv);
                assert!(
                    plan.effects
                        .iter()
                        .all(|effect| effect.operation.0 == "process.exec"),
                    "{argv:?}"
                );
                assert!(plan.boundaries.is_empty(), "{argv:?}");
            }
        }
    }
    for option in [
        "--reportformat",
        "--config",
        "--commandprofile",
        "--profile",
        "--devices",
        "--devicesfile",
        "-A",
        "--autobackup",
        "--driverloaded",
        "--journal",
        "--lockopt",
    ] {
        for argv in [vec!["lvremove", option], vec!["lvremove", option, "value"]] {
            assert!(
                exec(&argv)
                    .effects
                    .iter()
                    .all(|effect| effect.operation.0 == "process.exec"),
                "{argv:?}"
            );
        }
        for value in ["value", "--test", "--help"] {
            for argv in [
                vec!["lvremove", option, value, "vg/data"],
                vec!["lvm", option, value, "lvremove", "vg/data"],
            ] {
                let plan = exec(&argv);
                let effects: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "system.storage_destroy")
                    .collect();
                assert_eq!(effects.len(), 1, "{argv:?}");
                assert_eq!(
                    effinterp_proto::display_resource(&effects[0].resource),
                    "vol:lvm/vg/data",
                    "{argv:?}"
                );
                assert!(effects[0].attributes.is_empty(), "{argv:?}");
                assert!(effects[0].provenance.iter().any(|node| matches!(&plan.provenance[node.0 as usize].kind, effinterp_proto::ProvenanceKind::Argument { index, .. } if *index as usize == argv.len() - 1)), "{argv:?}");
            }
        }
    }
    for argv in [
        vec!["lvremove", "--reportformat=json", "vg/data"],
        vec!["lvremove", "--reportform", "json", "vg/data"],
        vec!["lvremove", "-fyAn", "vg/data"],
        vec!["lvremove", "--", "--test"],
    ] {
        let plan = exec(&argv);
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "system.storage_destroy")
            .unwrap();
        assert!(effect.attributes.is_empty(), "{argv:?}");
        assert_eq!(
            effinterp_proto::display_resource(&effect.resource),
            format!("vol:lvm/{}", argv.last().unwrap())
        );
    }
    for argv in [
        vec!["lvremove", "--select", "lv_name=data"],
        vec!["lvremove", "-Slv_name=data"],
        vec!["lvremove", "@selected"],
        vec!["lvremove", "--unknown", "json"],
        vec!["pvremove", "myvg"],
        vec!["lvm", "pvremove", "disk"],
    ] {
        let plan = exec(&argv);
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 == "process.exec"),
            "{argv:?}"
        );
        assert_eq!(plan.boundaries.len(), 1, "{argv:?}");
    }
}

#[test]
fn zpool_destroy_deletes_the_pool() {
    let plan = exec(&["zpool", "destroy", "tank"]);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "system.storage_destroy")
    );
}

#[test]
fn unmodeled_storage_subcommands_keep_filesystem_coverage_partial() {
    for argv in [
        vec!["zpool", "status"],
        vec!["zpool", "create", "tank", "/dev/sda"],
        vec!["zfs", "receive", "tank/data"],
        vec!["zfs", "rollback", "tank/data"],
        vec!["zpool", "rollback", "tank/data@snap"],
        vec!["zpool", "destroy", "-n", "tank"],
        vec!["lvm", "lvcreate", "-n", "new", "vg"],
        vec!["btrfs", "device", "add", "/dev/sdb", "/mnt"],
        vec!["btrfs", "receive", "/mnt"],
    ] {
        let plan = exec(&argv);
        assert!(plan.effects.iter().all(|e| e.operation.0 == "process.exec"));
        let boundary = plan
            .boundaries
            .iter()
            .find(|b| b.reason.as_str() == "unmodeled_subcommand")
            .unwrap();
        for domain in ["filesystem", "process", "system"] {
            let domain = effinterp_proto::Domain::new(domain);
            assert!(boundary.domains.contains(&domain), "{argv:?}");
            assert_eq!(
                plan.coverage.level(&domain),
                Some(effinterp_proto::CoverageLevel::Partial),
                "{argv:?}"
            );
        }
    }
}

#[test]
fn blkdiscard_writes_device() {
    let plan = exec(&["blkdiscard", "/dev/nvme0n1"]);
    assert!(has_effect_on(&plan, "filesystem.write", "nvme0n1"));
}

#[test]
fn partition_tools_write_the_device_with_an_explicit_operations_boundary() {
    for argv in [
        &["fdisk", "/dev/sdd"][..],
        &["sgdisk", "--zap-all", "/dev/sde"][..],
    ] {
        let plan = exec(argv);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.write"
                    && effect.attributes.get("partition_table") == Some(&AttrValue::Bool(true))
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == argv.last().unwrap())
            }),
            "{argv:?}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unparsed_partition_ops"),
            "{argv:?}"
        );
    }
}

#[test]
fn partition_report_modes_read_the_device_without_a_table_write() {
    for argv in [
        &["fdisk", "-l", "/dev/sda"][..],
        &["fdisk", "-lu", "/dev/sda"],
        &["sgdisk", "--print", "/dev/sda"],
        &["sgdisk", "-i1", "/dev/sda"],
        &["gdisk", "-l", "/dev/sda"],
        &["sfdisk", "--dump", "/dev/sda"],
        &["fdisk", "-l", "-u=sectors", "/dev/sda"],
        &["fdisk", "-l", "-o", "Device,Size", "/dev/sda"],
        &["fdisk", "--list-details", "/dev/sda"],
        // A list mode exits before its wipe policy could apply.
        &["fdisk", "-l", "-w", "always", "/dev/sda"],
        &["parted", "/dev/sda", "unit", "s", "print"],
        &["parted", "/dev/sda", "print", "free"],
        // An optional -u argument ends its cluster.
        &["fdisk", "-lu=sectors", "/dev/sda"],
        &["fdisk", "-l", "--bytes", "/dev/sda"],
        &["fdisk", "-lc=dos", "/dev/sda"],
        &["fdisk", "-l", "-c=dos", "--color=never", "/dev/sda"],
        &["sfdisk", "--dump", "--quiet", "/dev/sda"],
        &["sfdisk", "--no-act", "-l", "--color=never", "/dev/sda"],
        // Scripting settings do not turn a report into a script.
        &["sfdisk", "--dump", "-N", "1", "/dev/sda"],
        &["sfdisk", "-N", "1", "--dump", "/dev/sda"],
        &["sfdisk", "--dump", "--label", "gpt", "/dev/sda"],
        &["sfdisk", "--dump", "--wipe", "always", "/dev/sda"],
        // A getter prints the partition's value; its number is no path.
        &["sfdisk", "--part-type", "/dev/sda", "1"],
    ] {
        let plan = exec(argv);
        assert!(
            has_effect_on(&plan, "filesystem.read", "/dev/sda"),
            "{argv:?}"
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0.starts_with("filesystem."))
                .count(),
            1,
            "{argv:?}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write"),
            "{argv:?}"
        );
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    // The backup lands in the named file; the device is only read.
    let plan = exec(&["sgdisk", "--backup=/tmp/sda.gpt", "/dev/sda"]);
    assert!(has_effect_on(&plan, "filesystem.write", "/tmp/sda.gpt"));
    assert!(!has_effect_on(&plan, "filesystem.write", "/dev/sda"));
    // A report flag does not excuse an option that changes the table.
    for argv in [
        &["sgdisk", "-p", "--zap-all", "/dev/sda"][..],
        &["sgdisk", "-pZ", "/dev/sda"],
        &["fdisk", "-w", "always", "/dev/sda"],
        &["parted", "/dev/sda", "print", "rm", "1"],
        &["parted", "/dev/sda", "unit", "s", "mklabel", "gpt"],
        // The letters after an optional -u are its argument, not -l.
        &["fdisk", "-ul", "/dev/sda"],
        &["fdisk", "-c", "/dev/sda"],
        &["sfdisk", "--part-type", "/dev/sda", "1", "83"],
        // -N without an action scripts that one partition.
        &["sfdisk", "-N", "1", "/dev/sda"],
    ] {
        let plan = exec(argv);
        assert!(
            has_effect_on(&plan, "filesystem.write", "/dev/sda"),
            "{argv:?}"
        );
    }
    // A substitution could expand to an option such as -Z.
    for source in [
        r#"sgdisk -p "$(cat flags)" /dev/sda"#,
        "sgdisk -p $(cat flags) /dev/sda",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            has_effect_on(&plan, "filesystem.write", "/dev/sda"),
            "{source}"
        );
    }
}

#[test]
fn sfdisk_delete_writes_only_the_partition_table_unless_no_act() {
    for argv in [
        &["sfdisk", "--delete", "/dev/sda"][..],
        &["/usr/sbin/sfdisk", "--delete", "/tmp/disk.img", "1", "3"],
    ] {
        let plan = exec(argv);
        assert!(has_effect_on(&plan, "filesystem.write", argv[2]));
        assert!(attr(&plan, "filesystem.write", "partition_table"));
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "filesystem.write")
                .count(),
            1
        );
        assert!(!plan.effects.iter().any(|effect| matches!(
            effect.operation.0.as_str(),
            "filesystem.delete" | "system.storage_destroy"
        )));
        assert!(plan.boundaries.is_empty());
    }
    for argv in [
        &["sfdisk", "--no-act", "--delete", "/dev/sda"][..],
        &["sfdisk", "--delete", "-n", "/dev/sda", "1"],
    ] {
        let plan = exec(argv);
        assert!(has_effect_on(&plan, "filesystem.read", "/dev/sda"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write")
        );
        assert!(plan.boundaries.is_empty());
    }
    for argv in [
        &["sfdisk", "--delete"][..],
        &["sfdisk", "--delete", "/dev/sda", "/dev/sdb"],
        &["sfdisk", "--delete", "/dev/sda", "0"],
        &["sfdisk", "--delete", "--unknown", "/dev/sda"],
        &["sfdisk", "--delete=bad", "/dev/sda"],
    ] {
        let plan = exec(argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write"),
            "{argv:?}"
        );
        assert_eq!(plan.boundaries.len(), 1, "{argv:?}");
    }
    // Without --delete, sfdisk writes the table its input script describes;
    // --no-act runs everything but that write.
    for argv in [
        &["sfdisk", "/dev/sda"][..],
        &["sfdisk", "--wipe", "always", "/dev/sda"],
    ] {
        let plan = exec(argv);
        assert!(
            has_effect_on(&plan, "filesystem.write", "/dev/sda"),
            "{argv:?}"
        );
        assert!(attr(&plan, "filesystem.write", "partition_table"));
    }
    for argv in [
        &["sfdisk", "--no-act", "/dev/sda"][..],
        &["sfdisk", "-n", "--color=never", "/dev/sda"],
    ] {
        let preview = exec(argv);
        assert!(
            has_effect_on(&preview, "filesystem.read", "/dev/sda"),
            "{argv:?}"
        );
        assert!(
            !has_effect_on(&preview, "filesystem.write", "/dev/sda"),
            "{argv:?}"
        );
    }
}

#[test]
fn git_prune_expire_now_is_recovery_destroy() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: ["git", "prune", "--expire=now"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            cwd: Some("/repo".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "git.recovery_destroy")
    );
}

#[test]
fn git_prune_dry_run_is_a_read() {
    let plan = exec(&["git", "prune", "--dry-run"]);
    assert!(plan.effects.iter().any(|e| e.operation.0 == "git.read"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "git.recovery_destroy")
    );
}

#[test]
fn storage_destroy_keeps_volume_names_and_layers_device_writes() {
    for (argv, resource, attributes) in [
        (
            vec!["lvremove", "-f", "vg/data"],
            "vol:lvm/vg/data",
            serde_json::json!({}),
        ),
        (
            vec!["lvremove", "--test", "vg/data"],
            "vol:lvm/vg/data",
            serde_json::json!({"dry_run":true}),
        ),
        (
            vec!["lvremove", "-t", "vg/data"],
            "vol:lvm/vg/data",
            serde_json::json!({"dry_run":true}),
        ),
        (
            vec!["lvm", "vgremove", "archive"],
            "vol:lvm/archive",
            serde_json::json!({}),
        ),
        (
            vec!["pvremove", "/dev/sda"],
            "blk:/dev/sda",
            serde_json::json!({"whole_device":true}),
        ),
        (
            vec!["lvm", "--test", "lvremove", "vg/data"],
            "vol:lvm/vg/data",
            serde_json::json!({"dry_run":true}),
        ),
        (
            vec!["lvm", "--config", "global {}", "-t", "pvremove", "/dev/sda"],
            "blk:/dev/sda",
            serde_json::json!({"dry_run":true,"whole_device":true}),
        ),
        (
            vec!["zfs", "destroy", "-n", "tank/data@snap"],
            "vol:zfs/tank/data@snap",
            serde_json::json!({"dry_run":true}),
        ),
        (
            vec!["zfs", "destroy", "-nr", "tank/data"],
            "vol:zfs/tank/data",
            serde_json::json!({"dry_run":true,"recursive":true}),
        ),
        (
            vec!["zfs", "destroy", "-r", "tank/data"],
            "vol:zfs/tank/data",
            serde_json::json!({"recursive":true}),
        ),
        (
            vec!["zfs", "destroy", "-R", "-d", "tank/data@snap"],
            "vol:zfs/tank/data@snap",
            serde_json::json!({"recursive":true}),
        ),
        // Rollback rewinds the dataset holding the snapshot rather than
        // destroying it, and -r destroys the snapshots newer than the target.
        (
            vec!["zfs", "rollback", "-r", "tank/data@snap"],
            "vol:zfs/tank/data",
            serde_json::json!({
                "mode": "rollback",
                "newer_snapshots_destroyed": true,
                "snapshot": "tank/data@snap",
            }),
        ),
        (
            vec!["zfs", "rollback", "tank/data@snap"],
            "vol:zfs/tank/data",
            serde_json::json!({"mode": "rollback", "snapshot": "tank/data@snap"}),
        ),
        (
            vec!["zpool", "destroy", "tank"],
            "vol:zfs/tank",
            serde_json::json!({}),
        ),
        (
            vec!["btrfs", "subvolume", "delete", "/snapshots/one"],
            "vol:btrfs//snapshots/one",
            serde_json::json!({}),
        ),
    ] {
        let plan = exec(&argv);
        let effect = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "system.storage_destroy")
            .unwrap();
        assert_eq!(
            effinterp_proto::display_resource(&effect.resource),
            resource,
            "{argv:?}"
        );
        assert_eq!(
            serde_json::to_value(&effect.attributes).unwrap(),
            attributes
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.delete")
        );
    }
    for argv in [
        vec!["dd", "of=/dev/sda"],
        vec!["mkfs.ext4", "/dev/sda"],
        vec!["wipefs", "-a", "/dev/sda"],
        vec!["blkdiscard", "/dev/sda"],
        vec!["shred", "/dev/sda"],
        vec!["sgdisk", "--zap-all", "/dev/sda"],
        vec!["sgdisk", "-o", "/dev/sda"],
        vec!["hdparm", "--security-erase", "pass", "/dev/sda"],
        vec![
            "hdparm",
            "--user-master",
            "u",
            "--security-erase-enhanced",
            "p",
            "/dev/sda",
        ],
    ] {
        let plan = exec(&argv);
        assert!(has_effect_on(&plan, "filesystem.write", "/dev/sda"));
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "system.storage_destroy"
                    && effinterp_proto::display_resource(&e.resource) == "blk:/dev/sda")
        );
        assert!(attr(&plan, "system.storage_destroy", "whole_device"));
    }
    // diskutil names the disk by its node or its bare BSD name.
    for argv in [
        vec!["diskutil", "eraseDisk", "APFS", "Test", "/dev/disk0"],
        vec!["diskutil", "erasedisk", "JHFS+", "Test", "GPT", "disk0"],
        vec!["diskutil", "zeroDisk", "disk0"],
        vec!["diskutil", "secureErase", "0", "/dev/disk0"],
    ] {
        let plan = exec(&argv);
        assert!(
            has_effect_on(&plan, "filesystem.write", "/dev/disk0"),
            "{argv:?}"
        );
        assert!(
            attr(&plan, "system.storage_destroy", "whole_device"),
            "{argv:?}"
        );
    }
    for argv in [
        vec!["diskutil", "list"],
        vec!["hdparm", "-I", "/dev/sda"],
        vec!["diskutil", "eraseVolume", "APFS", "Test", "disk0s2"],
    ] {
        assert!(
            !exec(&argv)
                .effects
                .iter()
                .any(|e| e.operation.domain() == "system"),
            "{argv:?}"
        );
    }
    assert!(
        !exec(&["dd", "of=out.img"])
            .effects
            .iter()
            .any(|e| e.operation.domain() == "system")
    );
    let invalid_deferred_dataset = exec(&["zfs", "destroy", "-r", "-d", "tank/data"]);
    assert!(
        invalid_deferred_dataset
            .effects
            .iter()
            .all(|effect| effect.operation.0 == "process.exec")
    );
    assert!(invalid_deferred_dataset.boundaries.is_empty());
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "lvremove \"$VOLUME\"".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "system.storage_destroy"
                && effinterp_proto::display_resource(&e.resource) == "<sys:?>")
    );
}

#[test]
fn badblocks_write_mode_destroys_the_device() {
    for argv in [
        &["badblocks", "-w", "/dev/sda"][..],
        &["badblocks", "-wsv", "-b4096", "/dev/sda"][..],
        &["badblocks", "-b", "4096", "/dev/sda", "-w"][..],
    ] {
        let plan = exec(argv);
        assert!(
            has_effect_on(&plan, "filesystem.write", "/dev/sda"),
            "{argv:?}"
        );
        assert!(attr(&plan, "filesystem.write", "raw_device"), "{argv:?}");
        assert!(
            attr(&plan, "system.storage_destroy", "whole_device"),
            "{argv:?}"
        );
    }
    let plan = exec(&["badblocks", "-o", "bad.txt", "/dev/sda"]);
    assert!(has_effect_on(&plan, "filesystem.read", "/dev/sda"));
    assert!(has_effect_on(&plan, "filesystem.write", "/w/bad.txt"));
    // The non-destructive mode rewrites and restores each block; the write
    // modes are exclusive, and an unknown option exits with usage.
    let plan = exec(&["badblocks", "-n", "/dev/sda"]);
    assert!(has_effect_on(&plan, "filesystem.read", "/dev/sda"));
    assert!(!plan.boundaries.is_empty());
    for argv in [
        &["badblocks", "-w", "-n", "/dev/sda"][..],
        &["badblocks", "-w", "-Q", "/dev/sda"][..],
    ] {
        assert!(
            exec(argv)
                .effects
                .iter()
                .all(|e| e.operation.0 == "process.exec"),
            "{argv:?}"
        );
    }
}

#[test]
fn cryptsetup_luks_format_overwrites_the_device() {
    let plan = exec(&["cryptsetup", "luksFormat", "/dev/sda", "key.bin"]);
    assert!(has_effect_on(&plan, "filesystem.write", "/dev/sda"));
    assert!(attr(&plan, "filesystem.write", "raw_device"));
    assert!(has_effect_on(&plan, "filesystem.read", "/w/key.bin"));
    let plan = exec(&["cryptsetup", "luksFormat", "/dev/sda", "-"]);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read")
    );
}
