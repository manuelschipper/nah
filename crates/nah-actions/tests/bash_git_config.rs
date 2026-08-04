mod support;

use nah_actions::finalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect, Sensitivity};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> nah_proto::action::ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

#[test]
fn static_git_aliases_preserve_the_effects_they_execute() {
    for source in [
        "git -c 'alias.wipe=reset --hard' wipe",
        "git -c 'alias.wipe=reset \"--hard\"' wipe",
        "git -c alias.wipe=reset wipe --hard",
        "git -c alias.first=second -c 'alias.second=reset --hard' first",
        "git -c 'ALIAS.WIPE=reset --hard' WiPe",
    ] {
        let stream = stream(source);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Git { operation } if operation.as_str() == "hard-reset"
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let shell = stream("git -c 'alias.wipe=!rm -rf /' wipe");
    assert!(shell.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == absolute("/")
                    && effect.recursive
        )
    }));

    let self_disable = stream("git -c 'alias.off=!nah guard disable fs-root' off");
    assert!(self_disable.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. }
            } if operation.as_str() == "critical-mutation"
        )
    }));
}

#[test]
fn static_gc_expiry_configuration_obeys_last_wins_and_cli_overrides() {
    for source in [
        "git -c gc.pruneExpire=now gc",
        "git -c gc.pruneExpire=NOW gc",
        "git -cGC.PRUNEEXPIRE=0 gc",
        "git -c gc.pruneExpire=never -c gc.pruneExpire=now gc",
        "git prune --expire=NOW",
        "git prune --expire=never --expire=now",
        "git reflog expire --all --expire=never --expire=now",
    ] {
        let stream = stream(source);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Git { operation } if operation.as_str() == "recovery-destroy"
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "git -c user.name=Alice status",
        "git -c gc.pruneExpire=now -c gc.pruneExpire=never gc",
        "git -c gc.pruneExpire=now gc --no-prune",
        "git -c gc.pruneExpire=now gc --prune=2.weeks.ago",
        "git gc --prune=now --prune=never",
        "git prune --expire=now --expire=never",
        "git reflog expire --all --expire=now --expire=never",
        "git -c 'alias.wipe=reset --hard' wipe --help",
        "git -c 'alias.wipe=reset --hard' --help wipe",
        "git -c 'alias.status=reset --hard' status",
        "git -c 'alias.merge=reset --hard' merge",
        "git -c 'alias.archive=reset --hard' archive",
        "git push --dry-run --mirror origin",
    ] {
        let stream = stream(source);
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Git { operation }
                        if matches!(
                            operation.as_str(),
                            "hard-reset" | "recovery-destroy" | "force-push"
                        )
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
    assert_eq!(
        stream("git -c user.name=Alice status").coverage(),
        Coverage::Full
    );
}

#[test]
fn clean_force_configuration_is_bounded_and_last_wins() {
    for value in ["", "false", "FALSE", "no", "off", "0"] {
        let source = format!("git -c clean.requireForce={value} clean");
        let stream = stream(&source);
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "clean-force")
        }), "{source}: {:?}", stream.effects());
    }

    for source in [
        "git -c clean.requireForce=false -c clean.requireForce=true clean",
        "git -c clean.requireForce=maybe clean",
        "git -c clean.requireForce=false clean -n",
    ] {
        let stream = stream(source);
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "clean-force")
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
    assert_eq!(
        stream("git -c clean.requireForce=maybe clean").coverage(),
        Coverage::Partial
    );
}

#[test]
fn dynamic_git_configuration_is_partial_and_never_guessed() {
    for source in [
        "git -c \"user.name=$NAME\" status",
        "git -c \"alias.wipe=$ALIAS\" wipe",
        "git --config-env=alias.wipe=ALIAS wipe",
        "git -c 'alias.wipe=reset --hard' \"$COMMAND\"",
        "git -c \"alias.wipe=reset \\$'--hard'\" wipe",
        "git gc --prune=now \"$OPTIONS\"",
        "git prune --expire=now \"$OPTIONS\"",
        "git reflog expire --all --expire=now \"$OPTIONS\"",
        "git -c gc.pruneExpire=now gc --prune=\"$DATE\"",
        "git -c alias.x=x x",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Git { operation } if operation.as_str() == "hard-reset"
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn historical_secret_paths_and_bare_repository_metadata_stay_visible() {
    for source in [
        "git cat-file blob HEAD:.env",
        "git cat-file -p HEAD:.ssh/id_rsa",
        "git cat-file --textconv HEAD:.npmrc",
    ] {
        let stream = stream(source);
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Read
                        && effect.sensitivity != Sensitivity::None
            )
        }));
    }

    for source in [
        "rm -rf backup.git",
        "rm -rf backup.git/objects",
        "echo corrupt > backup.git/refs/heads/main",
    ] {
        let stream = stream(source);
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Git { operation } if operation.as_str() == "metadata-mutation"
            )
        }));
    }

    for source in [
        "touch backup.git",
        "rm -f backup.git",
        "rm -rf assets.git/index",
        "rm -rf objects",
    ] {
        assert!(!stream(source).effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Git { operation } if operation.as_str() == "metadata-mutation"
            )
        }));
    }
}
