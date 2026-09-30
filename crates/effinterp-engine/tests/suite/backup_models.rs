use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, Effect, ExecutionAssurance, ExecutionRealm, Modality, Plan, ResourceExpr, Subject,
    display_resource, validate_plan,
};

fn shell(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn backup_effects(plan: &Plan) -> Vec<&Effect> {
    plan.effects
        .iter()
        .filter(|e| e.attributes.contains_key("backup_action"))
        .collect()
}

fn attr(effect: &Effect, key: &str, expected: AttrValue) {
    assert_eq!(effect.attributes.get(key), Some(&expected), "{effect:?}");
}

#[test]
fn backup_safe_invalid_and_unknown_controls_do_not_invent_destruction() {
    for source in [
        "borg delete --help /backups",
        "borg delete --dry-run /backups",
        "borg delete --dry-run=false /backups",
        "borg delete --stats --quick-stats /backups",
        "borg delete --cache-only /backups",
        "borg -r /backups repo-delete --dry-run",
        "borg -r /backups repo-delete --yes",
        "borg -r /backups repo-delete --stats",
        "borg -r /backups delete",
        "borg delete --first 0 /backups",
        "borg delete --first nope /backups",
        "borg delete /backups::bad/archive",
        "borg -r /backups delete bad/archive",
        "borg -r /backups delete -a re:[",
        "borg prune -d 2 --keep-daily 7 /backups",
        "borg delete -a daily /backups::daily",
        "borg prune --keep-daily 0 /backups",
        "borg prune --keep-daily nope /backups",
        "borg compact /backups",
        "BORG_REPO=/backups borg delete",
        "borg delete --unknown /backups",
        "borg -r /backups repo-delete $FLAGS",
        "restic -r /backups forget --help abc123",
        "restic -r /backups forget --dry-run abc123",
        "restic -r /backups forget --no-lock abc123",
        "restic -r /backups forget --unsafe-allow-remove-all=false --tag old",
        "restic -r /backups forget --unsafe-allow-remove-all=true",
        "restic -r /backups forget --unsafe-allow-remove-all=bogus --tag old",
        "restic -r /backups forget --unsafe-allow-remove-all=$ALLOW --tag old",
        "restic -r /backups forget --unsafe-allow-remove-all=true --unsafe-allow-remove-all=false --tag old",
        "restic -r /backups forget abc123 --tag old",
        "restic -r /backups forget abc123 --host workstation",
        "restic -r /backups forget --keep-last unlimited",
        "restic -r /backups forget --keep-daily -1",
        "restic -r /backups forget --keep-daily 0",
        "restic -r /backups forget --keep-daily 18446744073709551615",
        "restic -r /backups forget --keep-daily bogus --keep-daily 7",
        "restic -r /backups forget --group-by invalid abc123",
        "restic -r /backups forget not-an-id",
        "RESTIC_REPOSITORY=/backups restic -r '' forget abc123",
        "RESTIC_REPOSITORY=/backups restic -r $REPO forget abc123",
        "restic -r s3:invalid forget abc123",
        "restic -r local: forget abc123",
        "restic -r rclone:remote:repo forget abc123",
        "restic -r /backups prune",
        "restic -r /backups delete",
        "velero backup delete --help --all",
        "velero backup delete --all=false",
        "velero backup delete --all=true --all=false",
        "velero backup delete --all=$ALL",
        "velero backup delete --all=invalid --all=true",
        "velero backup delete --all --confirm=invalid",
        "velero backup delete --all --dry-run",
        "velero backup delete --all --selector app=api",
        "velero backup delete --all backup-1",
        "velero backup delete --selector app=api backup-1",
        "velero backup delete --selector =api",
        "velero backup delete --selector invalid --selector app=api",
        "velero backup delete --selector app=$APP",
        "velero backup delete",
        "velero backup get --all",
    ] {
        let plan = shell(source);
        assert!(
            backup_effects(&plan).is_empty(),
            "{source}: {:?}",
            plan.effects
        );
        assert!(!plan.boundaries.is_empty(), "{source}: unexplained plan");
    }
}

#[test]
fn borg_repository_destruction_does_not_conflate_archive_selection() {
    for (source, whole, archive) in [
        (
            "borg delete --verbose --progress --stats --log-json /backups",
            true,
            None,
        ),
        ("borg delete --list /backups", true, None),
        ("borg -r /backups repo-delete --force", true, None),
        ("BORG_REPO=/backups borg repo-delete --force", true, None),
        ("borg delete /backups::daily", false, Some("daily")),
        ("borg delete /backups daily", false, Some("daily")),
        ("borg delete -a 'daily-*' /backups", false, None),
        ("borg prune --keep-daily 7 /backups", false, None),
        ("borg -r /backups delete daily", false, Some("daily")),
        ("borg -r /backups delete -a 'sh:daily-*'", false, None),
    ] {
        let plan = shell(source);
        let effects = backup_effects(&plan);
        assert_eq!(effects.len(), 1, "{source}: {plan:?}");
        let e = effects[0];
        assert_eq!(e.operation.as_str(), "filesystem.delete", "{source}");
        assert_eq!(e.modality, Modality::May, "{source}");
        attr(e, "whole_repository", AttrValue::Bool(whole));
        attr(e, "all_requested", AttrValue::Bool(whole));
        // Archive selection leaves the repository itself in place, and Borg 2
        // keeps the selected archives recoverable until `borg compact`.
        attr(e, "soft_delete", AttrValue::Bool(!whole));
        attr(e, "unsafe_allow_remove_all", AttrValue::Bool(false));
        attr(e, "repository", AttrValue::String("/backups".into()));
        if whole {
            assert_eq!(display_resource(&e.resource), "fs:/backups");
        } else {
            assert!(matches!(e.resource, ResourceExpr::Unresolved { .. }));
        }
        if let Some(archive) = archive {
            attr(e, "archive", AttrValue::String(archive.into()));
        }
    }
}

#[test]
fn restic_preserves_effective_allow_all_without_claiming_repository_or_count() {
    for (source, allow, all) in [
        ("restic -r /backups forget abc123", false, false),
        (
            "RESTIC_REPOSITORY=/backups restic forget abc123",
            false,
            false,
        ),
        (
            "restic -r /backups forget --unsafe-allow-remove-all=false abc123",
            false,
            false,
        ),
        (
            "restic -r /backups forget --unsafe-allow-remove-all=true abc123",
            true,
            false,
        ),
        ("restic -r /backups forget latest --tag old", false, false),
        (
            "restic -r /backups forget latest --host workstation --path /srv",
            false,
            false,
        ),
        (
            "restic -r /backups forget --keep-daily 7 --prune=false",
            false,
            false,
        ),
        (
            "restic -r /backups forget --unsafe-allow-remove-all=true --keep-daily 7",
            true,
            false,
        ),
        (
            "restic -r /backups forget --unsafe-allow-remove-all=true --tag old",
            true,
            true,
        ),
        (
            "restic -r /backups forget --unsafe-allow-remove-all=false --unsafe-allow-remove-all=true --tag old",
            true,
            true,
        ),
        (
            "restic -r /backups forget --dry-run=true --dry-run=false --no-lock=false abc123",
            false,
            false,
        ),
        (
            "restic -r /backups forget --keep-last unlimited abc123",
            false,
            false,
        ),
    ] {
        let plan = shell(source);
        let effects = backup_effects(&plan);
        assert_eq!(effects.len(), 1, "{source}: {plan:?}");
        let e = effects[0];
        assert_eq!(e.operation.as_str(), "filesystem.delete");
        assert_eq!(e.modality, Modality::May);
        assert!(matches!(e.resource, ResourceExpr::Unresolved { .. }));
        attr(e, "whole_repository", AttrValue::Bool(false));
        attr(e, "unsafe_allow_remove_all", AttrValue::Bool(allow));
        attr(e, "all_requested", AttrValue::Bool(all));
        assert!(!e.attributes.contains_key("removed_count"));
        assert!(!e.attributes.contains_key("count"));
    }
}

#[test]
fn backup_backends_keep_filesystems_remote_and_object_keys_unknown() {
    for (source, expected) in [
        (
            "restic forget abc123",
            &["RESTIC_REPOSITORY", "RESTIC_REPOSITORY_FILE"][..],
        ),
        ("borg repo-delete --force", &["BORG_REPO"][..]),
        (
            "restic -r /backups forget abc123",
            &["RESTIC_REPOSITORY_FILE"][..],
        ),
    ] {
        let plan = shell(source);
        let mut names = plan
            .effects
            .iter()
            .filter_map(|effect| {
                if effect.operation.as_str() != "environment.read" {
                    return None;
                }
                assert_eq!(
                    effect.request_assurance,
                    effinterp_proto::RequestAssurance::Conservative
                );
                match &effect.resource {
                    ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { name },
                    } => Some(name.as_str()),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, expected, "{source}");
    }
    for (source, op, remote) in [
        ("borg delete user@host:/backups", "filesystem.delete", true),
        (
            "borg -r ssh://user@host/backups repo-delete --force",
            "filesystem.delete",
            true,
        ),
        (
            "restic -r sftp:user@host:/backups forget abc123",
            "filesystem.delete",
            true,
        ),
        (
            "restic -r sftp://user@host//backups forget abc123",
            "filesystem.delete",
            true,
        ),
        (
            "restic -r s3:s3.amazonaws.com/bucket/prefix forget abc123",
            "cloud.object.delete",
            false,
        ),
        (
            "restic -r b2:bucket:prefix forget abc123",
            "cloud.object.delete",
            false,
        ),
        ("borg repo-delete", "filesystem.delete", false),
        ("restic forget abc123", "filesystem.delete", false),
        (
            "restic --repository-file /unobserved forget abc123",
            "filesystem.delete",
            false,
        ),
    ] {
        let plan = shell(source);
        let effects = backup_effects(&plan);
        assert_eq!(effects.len(), 1, "{source}: {plan:?}");
        let e = effects[0];
        assert_eq!(e.operation.as_str(), op);
        assert_eq!(matches!(e.realm, ExecutionRealm::Remote { .. }), remote);
        assert!(matches!(e.resource, ResourceExpr::Unresolved { .. }));
        assert_eq!(e.modality, Modality::May);
        if remote {
            let execution = &plan.execution_graph.nodes[e.execution.0 as usize];
            assert_eq!(execution.assurance, ExecutionAssurance::Widened);
            assert!(execution.boundary.is_some());
            assert!(matches!(
                execution.argv.as_slice(),
                [ResourceExpr::Unresolved { .. }]
            ));
        }
    }
    let plan = shell("test -f /flag && restic -r sftp:user@host:/backups forget abc123");
    let effects = backup_effects(&plan);
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].modality, Modality::May);
    assert!(effects[0].condition.is_some());
}

#[test]
fn velero_all_is_a_request_and_confirmation_is_not_proof_of_removal() {
    for (source, all, confirm, selection) in [
        (
            "velero backup delete --all=true --confirm=true",
            true,
            true,
            "all_backups",
        ),
        (
            "velero backup delete --all=false --all=true --confirm=false",
            true,
            false,
            "all_backups",
        ),
        (
            "velero backup delete backup-1 --confirm",
            false,
            true,
            "backup",
        ),
        (
            "velero backup delete backup-1 --all=false",
            false,
            false,
            "backup",
        ),
        (
            "velero backup delete --selector app=api --confirm",
            false,
            true,
            "selector",
        ),
        (
            "velero backup delete --selector '' --confirm=false",
            false,
            false,
            "selector",
        ),
        (
            "test -f /flag && velero backup delete --all --confirm",
            true,
            true,
            "all_backups",
        ),
    ] {
        let plan = shell(source);
        let effects = backup_effects(&plan);
        assert_eq!(effects.len(), 1, "{source}: {plan:?}");
        let e = effects[0];
        assert_eq!(e.operation.as_str(), "cloud.object.delete");
        assert_eq!(e.modality, Modality::May);
        assert!(matches!(e.resource, ResourceExpr::Unresolved { .. }));
        attr(e, "all_requested", AttrValue::Bool(all));
        attr(e, "confirm_requested", AttrValue::Bool(confirm));
        attr(e, "whole_repository", AttrValue::Bool(false));
        attr(e, "unsafe_allow_remove_all", AttrValue::Bool(false));
        attr(e, "selection", AttrValue::String(selection.into()));
        assert!(!e.attributes.contains_key("removed_count"));
        assert!(!e.attributes.contains_key("count"));
    }
}

#[test]
fn duplicity_removes_backup_sets_only_once_forced() {
    for (source, bucket, key) in [
        (
            "duplicity remove-older-than 30D s3://bucket --force",
            "bucket",
            None,
        ),
        (
            "duplicity remove-all-but-n-full 2 gs://bucket/prefix --force",
            "bucket",
            Some("prefix"),
        ),
        (
            "duplicity remove-all-inc-of-but-n-full 1 s3://bucket --force",
            "bucket",
            None,
        ),
    ] {
        let plan = shell(source);
        let effects = backup_effects(&plan);
        assert_eq!(effects.len(), 1, "{source}: {plan:?}");
        let e = effects[0];
        assert_eq!(e.operation.as_str(), "cloud.object.delete", "{source}");
        assert_eq!(e.modality, Modality::May, "{source}");
        attr(
            e,
            "backup_action",
            AttrValue::String("delete_backup_set".into()),
        );
        match &e.resource {
            ResourceExpr::Concrete {
                identity:
                    effinterp_proto::ResourceIdentity::ObjectStore {
                        bucket: named,
                        key: stored,
                        ..
                    },
            } => {
                assert_eq!(named, bucket, "{source}");
                assert_eq!(stored.as_deref(), key, "{source}");
            }
            other => panic!("{source}: {other:?}"),
        }
    }
    for source in [
        // Removal only reports the backup sets it would delete until --force.
        "duplicity remove-older-than 30D s3://bucket",
        "duplicity remove-older-than 30D s3://bucket --force --dry-run",
        "duplicity remove-older-than nope s3://bucket --force",
        "duplicity remove-all-but-n-full 0 s3://bucket --force",
        // Other backends and other commands are not typed here.
        "duplicity remove-older-than 30D scp://host/backups --force",
        "duplicity cleanup s3://bucket --force",
        "duplicity --unknown remove-older-than 30D s3://bucket --force",
    ] {
        let plan = shell(source);
        assert!(
            backup_effects(&plan).is_empty(),
            "{source}: {:?}",
            plan.effects
        );
        assert!(!plan.boundaries.is_empty(), "{source}: unexplained plan");
    }
}

#[test]
fn restic_keep_within_durations_are_retention_policies() {
    for (source, key, duration) in [
        ("restic forget --keep-within 7d", "keep-within", "7d"),
        (
            "restic forget --keep-within 0d --keep-last 2",
            "keep-within",
            "0d",
        ),
        (
            "restic forget --keep-within-daily 1y5m7d2h",
            "keep-within-daily",
            "1y5m7d2h",
        ),
    ] {
        let plan = shell(source);
        let [effect] = backup_effects(&plan)[..] else {
            panic!("{source}: {:?}", plan.boundaries);
        };
        attr(effect, "selection", AttrValue::String("retention".into()));
        attr(effect, key, AttrValue::String(duration.into()));
    }
    // An all-zero duration sets no policy, and restic rejects a negative or
    // unit-less duration before it removes anything.
    for source in [
        "restic forget --keep-within 0d",
        "restic forget --keep-within=-1d",
        "restic forget --keep-within 7",
        "restic forget --keep-within 7w",
    ] {
        assert!(backup_effects(&shell(source)).is_empty(), "{source}");
    }
}
