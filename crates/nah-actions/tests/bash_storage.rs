mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, FilesystemOperation, SemanticCode};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn has_system_state(source: &str, operation: &SemanticCode) -> bool {
    stream(source).effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::SystemState { operation: candidate } if candidate == operation)
    })
}

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

#[test]
fn whole_backup_repository_deletion_emits_storage_destroy() {
    for source in [
        "borg delete /srv/backups/repo",
        "borg delete --force /srv/backups/repo",
        "borg repo-delete --yes",
        "borg repo-delete -y",
        "restic forget --unsafe-allow-remove-all --tag old",
        "velero backup delete --all --confirm",
        "BORG_DELETE_I_KNOW_WHAT_I_AM_DOING=YES borg delete /srv/backups/repo",
        "printf 'y\\n' | borg repo-delete",
        "timeout 5 restic forget --unsafe-allow-remove-all",
        "/usr/bin/velero backup delete --all",
    ] {
        assert!(
            has_system_state(source, &SemanticCode::STORAGE_DESTROY),
            "{source}: {:?}",
            stream(source).effects()
        );
    }
}

#[test]
fn broad_remote_and_destination_deletion_emits_recursive_delete() {
    for source in [
        "aws s3 rb s3://bucket --force",
        "aws --profile prod s3 rm s3://bucket/prefix --recursive",
        "aws --region us-east-1 s3 sync build/ s3://site --delete",
        "aws --endpoint-url https://storage.example s3 sync build/ s3://site --delete",
        "aws --profile=prod s3 rm s3://bucket/prefix --recursive",
        "gcloud --project prod storage rm -r gs://bucket/prefix",
        "gcloud --project=prod storage rm --recursive gs://bucket/prefix",
        "gsutil -m rm -R gs://bucket/prefix",
        "gsutil -m rm -r gs://bucket/prefix",
        "gcloud storage rsync build/ gs://site --delete-unmatched-destination-objects",
        "gsutil -m rsync -dr build/ gs://site",
        "az storage container delete --account-name prod --name backups --yes",
        "az storage container delete --account-name=prod --name=backups --yes",
        "az storage account delete --name scratch --yes",
        "az storage blob delete-batch --account-name prod --source artifacts",
        "azcopy sync build https://account.blob.core.windows.net/site --delete-destination=true",
        "azcopy rm https://account.blob.core.windows.net/site --recursive",
        "azcopy rm https://account.blob.core.windows.net/site --recursive=true",
        "rclone --config /tmp/rclone.conf purge remote:old",
        "rclone --config=/tmp/rclone.conf delete remote:old",
        "rclone delete remote:old",
        "rclone sync . remote:mirror",
        "rsync -a --delete dist/ host:/var/www/",
        "rsync -a --del dist/ mirror/",
        "rsync -a --delete-before dist/ mirror/",
        "rsync -a --delete-during dist/ mirror/",
        "rsync -a --delete-delay dist/ mirror/",
        "rsync -a --delete-after dist/ mirror/",
        "rsync -a --delete-excluded dist/ mirror/",
        "rsync --delete -- dist/ mirror/",
        "/bin/rclone sync . remote:mirror",
        "PATH=/tmp /usr/bin/aws s3 rm s3://bucket --recursive",
    ] {
        assert!(
            has_system_state(source, &SemanticCode::STORAGE_RECURSIVE_DELETE),
            "{source}: {:?}",
            stream(source).effects()
        );
    }
}

#[test]
fn every_rsync_destination_delete_spelling_covers_local_and_remote_destinations() {
    for option in [
        "--delete",
        "--del",
        "--delete-before",
        "--delete-during",
        "--delete-delay",
        "--delete-after",
        "--delete-excluded",
    ] {
        for destination in ["mirror/", "host:/var/www/"] {
            let source = format!("rsync -a {option} dist/ {destination}");
            assert!(
                has_system_state(&source, &SemanticCode::STORAGE_RECURSIVE_DELETE),
                "{source}: {:?}",
                stream(&source).effects()
            );
        }
    }
}

#[test]
fn snapshot_and_retention_deletion_emits_snapshot_delete() {
    for source in [
        "zfs destroy tank/data@snap",
        "zfs destroy -R tank/data@a%b",
        "zfs destroy -- tank/data@snap",
        "zfs rollback -r tank/data@snap",
        "zfs rollback -R tank/data@snap",
        "btrfs subvolume delete /snapshots/one",
        "aws ec2 delete-snapshot --snapshot-id snap-1",
        "aws ec2 delete-volume --volume-id vol-1",
        "gcloud compute snapshots delete snap-1 --quiet",
        "gcloud compute disks delete disk-1 --zone us-east1-b",
        "az snapshot delete --name snap-1 --resource-group prod",
        "az disk delete --name disk-1 --resource-group prod --yes",
        "restic forget abc123",
        "restic forget --keep-daily 7 --prune",
        "borg delete /srv/repo::archive",
        "borg delete -a 'daily-*' /srv/repo",
        "borg delete --glob-archives 'daily-*' /srv/repo",
        "borg prune --keep-daily 7 /srv/repo",
        "duplicity remove-older-than 30D s3://bucket --force",
        "duplicity remove-all-but-n-full 2 s3://bucket --force",
        "duplicity remove-all-inc-of-but-n-full 2 s3://bucket --force",
        "velero backup delete backup-1 --confirm",
        "velero backup delete --selector app=api --confirm",
    ] {
        assert!(
            has_system_state(source, &SemanticCode::STORAGE_SNAPSHOT_DELETE),
            "{source}: {:?}",
            stream(source).effects()
        );
    }
}

#[test]
fn storage_controls_and_narrow_or_nonexecuting_forms_delegate() {
    for source in [
        "aws s3 rb s3://bucket",
        "aws s3api delete-bucket --bucket empty",
        "gsutil rb gs://empty",
        "gcloud storage buckets delete gs://empty",
        "rclone rmdir remote:empty",
        "rclone rmdirs remote:empty",
        "aws s3 rm s3://bucket/one.txt",
        "aws s3 cp file s3://bucket/file",
        "rclone copy . remote:copy",
        "rclone move . remote:copy",
        "rclone copyto file remote:file",
        "rclone deletefile remote:file",
        "rsync -a --remove-source-files src/ dest/",
        "aws s3api delete-objects --bucket b --delete-file file://objects.json",
        "aws s3api put-bucket-replication --bucket b",
        "aws s3api put-bucket-lifecycle-configuration --bucket b --lifecycle-configuration file://lifecycle.json",
        "zfs send tank/data@snap",
        "btrfs send /snapshots/one",
        "zfs receive -F tank/data",
        "restic prune",
        "borg compact /srv/repo",
        "borg delete --cache-only /srv/repo",
        "zfs rollback tank/data@snap",
        "velero restore delete restore-1",
        "velero backup-location delete default",
        "kubectl delete backup backup-1",
        "aws ec2 deregister-image --snapshot-id ami-1",
        "zfs snapshot tank/data@snap",
        "btrfs subvolume snapshot /data /snapshots/one",
        "restic backup /data",
        "borg create /srv/repo::archive /data",
        "aws s3 rm s3://bucket --recursive --help",
        "rclone sync src remote:dst --version",
    ] {
        let stream = stream(source);
        assert!(
            stream.effects().iter().all(|effect| !matches!(
                effect.kind(),
                EffectKind::SystemState { operation }
                    if matches!(
                        operation.as_str(),
                        "storage-destroy"
                            | "storage-recursive-delete"
                            | "storage-snapshot-delete"
                    )
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn dry_runs_filters_and_retained_copy_modes_delegate() {
    for source in [
        "aws s3 rm s3://bucket --recursive --dryrun",
        "aws s3 sync build/ s3://site --delete --exclude '*.map'",
        "gcloud storage rm -r gs://bucket --filter name:old",
        "gsutil rsync -dn -x 'keep' src gs://bucket",
        "az storage blob delete-batch --source artifacts --pattern '*.tmp'",
        "azcopy sync src dst --delete-destination=true --include-pattern '*.tmp'",
        "azcopy rm dst --recursive=true --dry-run",
        "rclone purge remote:old --filter '- keep/**'",
        "rclone delete remote:old --include '*.tmp'",
        "rclone sync src remote:dst --dry-run",
        "rclone sync src remote:dst -i",
        "rclone sync src remote:dst --backup-dir remote:backup",
        "rsync -an --delete src/ dst/",
        "rsync -a --delete --exclude keep src/ dst/",
        "rsync -a --delete --backup src/ dst/",
        "rsync -a --delete --backup-dir backup src/ dst/",
        "zfs destroy -n tank/data@snap",
        "restic forget abc123 --dry-run",
        "borg prune --dry-run /srv/repo",
        "borg prune --list /srv/repo",
        "duplicity remove-older-than 30D s3://bucket",
    ] {
        assert!(
            !has_system_state(source, &SemanticCode::STORAGE_RECURSIVE_DELETE)
                && !has_system_state(source, &SemanticCode::STORAGE_SNAPSHOT_DELETE),
            "{source}: {:?}",
            stream(source).effects()
        );
    }
}

#[test]
fn dynamic_malformed_and_untrusted_executable_forms_are_not_claimed() {
    for source in [
        "aws s3 rm \"$TARGET\" --recursive",
        "rclone \"$COMMAND\" src remote:dst",
        "rsync --delete src/ \"$DESTINATION\"",
        "borg delete",
        "restic forget --keep-daily",
        "velero backup delete",
        "aws s3 sync src --delete",
        "aws --profile s3 rm s3://bucket --recursive",
        "rclone sync src",
        "rclone sync src ''",
        "rsync --delete src",
        "aws s3 rm s3://bucket --unknown-selection value --recursive",
        "PATH=/tmp aws s3 rm s3://bucket --recursive",
        "/opt/aws s3 rm s3://bucket --recursive",
    ] {
        assert!(
            !has_system_state(source, &SemanticCode::STORAGE_DESTROY)
                && !has_system_state(source, &SemanticCode::STORAGE_RECURSIVE_DELETE)
                && !has_system_state(source, &SemanticCode::STORAGE_SNAPSHOT_DELETE),
            "{source}: {:?}",
            stream(source).effects()
        );
    }
}

#[test]
fn live_zfs_dataset_destroy_uses_the_existing_logical_storage_code() {
    for source in [
        "zfs destroy tank/data",
        "zfs destroy -r tank/data",
        "zfs destroy -Rf tank/data",
    ] {
        assert!(
            has_system_state(source, &SemanticCode::LOGICAL_STORAGE_DESTROY),
            "{source}: {:?}",
            stream(source).effects()
        );
        assert!(!has_system_state(
            source,
            &SemanticCode::STORAGE_SNAPSHOT_DELETE
        ));
    }
    for source in [
        "zfs destroy -n tank/data",
        "zfs destroy tank/data@snap",
        "zfs destroy tank/data#bookmark",
    ] {
        assert!(
            !has_system_state(source, &SemanticCode::LOGICAL_STORAGE_DESTROY),
            "{source}: {:?}",
            stream(source).effects()
        );
    }
}
