mod support;

use nah_actions::finalize;
use nah_proto::action::{EffectKind, FilesystemOperation, NahProtectionTier};
use support::{bash_plan, observe};

#[test]
fn common_mutators_expose_static_protected_destinations() {
    for source in [
        "sed -i 's/off/on/' ~/.nah/trust.json",
        "sed --in-place=.bak -e 's/off/on/' ~/.nah/activations.json",
        "ln -s replacement ~/.nah/trust.json",
        "install replacement ~/.nah/trust.json",
        "install -m 600 replacement ~/.nah/trust.json",
        "install -t ~/.nah replacement",
        "rsync -a replacement ~/.nah/trust.json",
        "rsync --remove-source-files ~/.nah/trust.json backup",
        "/usr/bin/objcopy /tmp/replacement ~/.nah/trust.json",
        "objcopy ~/.nah/trust.json",
        "objcopy --strip-all /tmp/replacement ~/.nah/trust.json",
        "objcopy --strip-debug ~/.nah/trust.json",
        "objcopy -S ~/.nah/trust.json",
        "/usr/bin/strip -o ~/.nah/trust.json /tmp/replacement",
        "strip --output-file=~/.nah/trust.json /tmp/replacement",
        "strip ~/.nah/trust.json",
        "strip --strip-debug ~/.nah/trust.json",
        "strip -s /tmp/ordinary ~/.nah/trust.json",
        "strip -s -o ~/.nah/trust.json /tmp/ordinary",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.protection == Some(NahProtectionTier::Critical)
                        && matches!(
                            effect.operation,
                            FilesystemOperation::Write | FilesystemOperation::Delete
                        )
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn reviewed_mutators_expose_static_protected_destinations() {
    for source in [
        "perl -pi -e 's/off/on/' ~/.nah/trust.json",
        "perl -pi \"$SCRIPT\" ~/.nah/trust.json",
        "gawk -i inplace '{ print }' ~/.nah/trust.json",
        "patch ~/.nah/trust.json fix.patch",
        "patch -i fix.patch -o ~/.nah/trust.json original",
        "ed ~/.nah/trust.json",
        "ex -sc wq ~/.nah/trust.json",
        "vim -es -c wq ~/.nah/trust.json",
        "chattr +i ~/.nah/trust.json",
        "cd ~/.nah && git restore trust.json",
        "cd ~/.nah && git checkout HEAD -- trust.json",
        "git -C ~/.nah checkout HEAD -- trust.json",
        "tar -xf bundle.tar -C ~/.nah",
        "unzip bundle.zip -d ~/.nah",
        "7z x bundle.7z -o~/.nah",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.protection == Some(NahProtectionTier::Critical)
                        && effect.operation == FilesystemOperation::Write
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn read_only_and_dynamic_forms_do_not_invent_protected_writes() {
    for source in [
        "sed 's/off/on/' ~/.nah/trust.json",
        "perl -pe 's/off/on/' ~/.nah/trust.json",
        "perl -Mstrict -pe 's/off/on/' ~/.nah/trust.json",
        "perl \"$SCRIPT\" -pi ~/.nah/trust.json",
        "gawk '{ print }' ~/.nah/trust.json",
        "patch --dry-run ~/.nah/trust.json fix.patch",
        "vim -es -c quit ~/.nah/trust.json",
        "git restore --staged ~/.nah/trust.json",
        "tar -tf bundle.tar",
        "unzip -l bundle.zip",
        "7z l bundle.7z",
        "ln -s replacement \"$DESTINATION\"",
        "install replacement \"$DESTINATION\"",
        "rsync replacement host:/tmp/trust.json",
        "perl -pi -e 's/off/on/' /tmp/.nah/trust.json",
        "objcopy ~/.nah/trust.json /tmp/copy",
        "objcopy /tmp/replacement \"$DESTINATION\"",
        "strip -o /tmp/stripped ~/.nah/trust.json",
        "strip --help ~/.nah/trust.json",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.protection == Some(NahProtectionTier::Critical)
                        && effect.operation == FilesystemOperation::Write
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}
