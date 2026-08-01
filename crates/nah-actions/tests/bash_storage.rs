mod support;

use nah_actions::finalize;
use nah_proto::action::{EffectKind, FilesystemOperation};
use support::{absolute, bash_plan, observe};

#[test]
fn definite_logical_storage_destruction_emits_typed_evidence() {
    for source in [
        "lvremove vg/data",
        "vgremove archive",
        "lvm lvremove vg/data",
        "lvm vgremove archive",
        "zpool destroy tank",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::SystemState { operation }
                    if operation.as_str() == "logical-storage-destroy"
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "lvremove --test vg/data",
        "lvremove -h vg/data",
        "lvremove --longhelp vg/data",
        "vgremove -t archive",
        "lvremove --reportformat json",
        "vgremove --config 'log { verbose=1 }'",
        "lvremove --select 'lv_name=data'",
        "lvremove --reportformat",
        "zpool status tank",
        "zpool destroy --dry-run tank",
        "lvremove \"$VOLUME\"",
        "lvm lvdisplay vg/data",
        "lvm vgs",
        "lvm --help",
        "lvm --test lvremove vg/data",
        "lvm lvremove --test vg/data",
        "lvm lvremove --reportformat json",
        "zpool destroy",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::SystemState { operation }
                    if operation.as_str() == "logical-storage-destroy"
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn storage_no_act_modes_emit_no_raw_write_and_active_controls_still_do() {
    for source in [
        "pvremove /dev/sda",
        "sfdisk --delete /dev/sda",
        "mkfs.ext4 /dev/sda",
        "cryptsetup luksFormat /dev/sda",
        "badblocks -w /dev/sda",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Write
                        && effect.target == absolute("/dev/sda")
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "pvremove --test /dev/sda",
        "sfdisk --no-act --delete /dev/sda",
        "sfdisk -n --delete /dev/sda",
        "mkfs -n /dev/sda",
        "mkfs.ext4 -n /dev/sda",
        "cryptsetup erase /dev/sda",
        "cryptsetup luksErase /dev/sda",
        "badblocks -n /dev/sda",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().all(|effect| !matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Write
                        && effect.target == absolute("/dev/sda")
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}
