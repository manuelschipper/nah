mod support;

use nah_actions::finalize;
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, HostIntegrityClass, InvocationEffect, Sensitivity,
};
use nah_proto::observation::ObservationFailure;
use support::{Change, absolute, bash_plan, observation_with, observe, observe_with_path_error};

#[test]
fn block_relevant_bash_paths_survive_permission_and_timeout_failures() {
    for failure in [
        ObservationFailure::PermissionDenied,
        ObservationFailure::Timeout,
    ] {
        for (source, expected) in [
            (
                "printf x > /home/test/.bashrc",
                Some(HostIntegrityClass::ShellProfile),
            ),
            ("rm /etc/passwd", Some(HostIntegrityClass::AuthIdentity)),
            ("cat /repo/.env", None),
        ] {
            let plan = bash_plan(source);
            let stream = finalize(
                plan.clone(),
                observe_with_path_error(plan.observation_request(), failure),
            );
            assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
            assert!(
                stream.effects().iter().any(|effect| matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.host_integrity == expected
                            && (expected.is_some() || effect.sensitivity != Sensitivity::None)
                )),
                "{source}: {:?}",
                stream.effects()
            );
        }

        let plan = bash_plan("printf x > /tmp/ordinary");
        let stream = finalize(
            plan.clone(),
            observe_with_path_error(plan.observation_request(), failure),
        );
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. })),
            "{failure:?}"
        );
    }
}

#[test]
fn visible_function_calls_and_coprocesses_preserve_destructive_bodies() {
    for source in [
        "f(){ rm -rf /; }; f",
        "function f { rm -rf /; }; f",
        "outer(){ inner(){ rm -rf /; }; inner; }; outer",
        "f(){ rm -rf /; f; }; f",
        "coproc rm -rf /",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/")
                        && effect.recursive
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "f(){ rm -rf /; }",
        "f(){ rm -rf /; }; f(){ :; }; f",
        "f(){ rm -rf /; }; unset -f f; f",
        "f(){ rm -rf /; }; command f",
        "f(){ rm -rf /; }; env f",
        "'coproc' rm -rf /",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/")
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = "f(){ :; } > /home/test/.nah/config; f";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(
        stream.effects().iter().any(|effect| matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/home/test/.nah/config")
        )),
        "{source}: {:?}",
        stream.effects()
    );

    let source = "f(){ :; } > /home/test/.nah/config";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(
        !stream.effects().iter().any(|effect| matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/home/test/.nah/config")
        )),
        "{source}: {:?}",
        stream.effects()
    );
}

#[test]
fn filesystem_and_fork_bomb_evidence_survives_partial_lowering() {
    for (source, operation, target, recursive, selects_home) in [
        ("rm -rf /", FilesystemOperation::Delete, "/", true, true),
        (
            "cd ~ && rm -rf .",
            FilesystemOperation::Delete,
            "/home/test",
            true,
            true,
        ),
        (
            "chmod -R 000 /etc",
            FilesystemOperation::Write,
            "/etc",
            true,
            false,
        ),
        (
            "chmod -R --reference --help /",
            FilesystemOperation::Write,
            "/",
            true,
            true,
        ),
        (
            "rm -rf /home",
            FilesystemOperation::Delete,
            "/home",
            true,
            true,
        ),
        (
            "dd if=/dev/zero of=/dev/sda",
            FilesystemOperation::Write,
            "/dev/sda",
            false,
            false,
        ),
        (
            "chown -h -R --reference=/tmp/ref /",
            FilesystemOperation::Write,
            "/",
            true,
            true,
        ),
        (
            "busybox rm -rf /",
            FilesystemOperation::Delete,
            "/",
            true,
            true,
        ),
        (
            "find / -delete",
            FilesystemOperation::Delete,
            "/",
            true,
            true,
        ),
        (
            "mkfs.ext4 /dev/loop0",
            FilesystemOperation::Write,
            "/dev/loop0",
            false,
            false,
        ),
        (
            "mkfs.ext4 /dev/dax0.0",
            FilesystemOperation::Write,
            "/dev/dax0.0",
            false,
            false,
        ),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.operation == operation
                            && effect.target == absolute(target)
                            && effect.recursive == recursive
                            && effect.selects_home == selects_home
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        ":(){ :|:& };:",
        "bomb(){ bomb& bomb& }; bomb",
        "bomb(){ bomb & }; bomb",
        "while true; do work & done",
        "for ((;;)); do work & done",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Partial);
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::SystemState { operation } if operation.as_str() == "fork-bomb"
            )
        }));
    }

    for source in [
        "bash -c 'rm -rf /'",
        "bash <<< 'rm -rf /'",
        "command -- rm -rf /",
        "env SAFE=1 rm -rf /",
        "sudo -u root rm -rf /",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.operation == FilesystemOperation::Delete
                            && effect.target == absolute("/")
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let plan = bash_plan("rm -rf \"$TARGET\"");
    let observation = observe(plan.observation_request(), "echo");
    assert_eq!(finalize(plan, observation).coverage(), Coverage::Partial);

    let plan = bash_plan("rm -rf ~");
    let observation = observation_with(
        plan.observation_request(),
        plan.observation_request().request_id(),
        Change::CanonicalHomeAlias,
    );
    let stream = finalize(plan, observation);
    assert!(stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.target == absolute("/private/home/test") && effect.selects_home
        )
    }));
}

#[test]
fn chmod_modes_distinguish_only_provable_permission_weakening() {
    for source in [
        "chmod 777 file",
        "chmod 00002 file",
        "chmod 4755 file",
        "chmod 02755 file",
        "chmod o+w file",
        "chmod a=rw file",
        "chmod ug+s file",
        "chmod a=rxs file",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "permission-weaken"
            )),
            "{source}: {:?}",
            stream.effects()
        );
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Write
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "chmod 755 file",
        "chmod 01755 file",
        "chmod u+x file",
        "chmod o-w file",
        "chmod u-s file",
        "chmod +w file",
        "chmod u+r,+w file",
        "chmod o+w-w file",
        "chmod --reference=reference file",
        "chmod \"$MODE\" file",
        "chmod u++w file",
        "chmod o+uw file",
        "chmod 12 file",
        "chmod 888 file",
        "chown user file",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "permission-change"
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = "find / -exec chmod 777 '{}' +";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { operation, .. }
        } if operation.as_str() == "permission-weaken"
    )));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target == absolute("/")
                && effect.recursive
    )));
}

#[test]
fn expanded_patterns_stay_unresolved_and_quoted_patterns_stay_literal() {
    for (source, target, pattern) in [
        ("rm -rf /et?", "/et?", true),
        ("rm -rf /et[c]", "/et[c]", true),
        ("rm -rf /{,}", "/{,}", true),
        ("rm -rf /etc/foo?", "/etc/foo?", true),
        ("rm -rf '/et?'", "/et?", false),
        ("rm -rf \"/et?\"", "/et?", false),
        ("rm -rf /et\\?", "/et?", false),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.target == absolute(target) && effect.pattern == pattern
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    // A pattern cannot escape the literal text before it: `/etc/foo?` reaches
    // no further than `/etc/foo`, so it must not widen to the system tree.
    assert_eq!(nah_proto::action::pattern_bound("/etc/foo?"), "/etc/foo");
    assert_eq!(nah_proto::action::pattern_bound("/et?"), "/et");
    assert_eq!(
        nah_proto::action::pattern_bound("/home/test/{,.ssh}"),
        "/home/test/"
    );
}

#[test]
fn every_home_variable_spelling_reaches_the_same_target() {
    for source in [
        "rm -rf \"$HOME\"/.ssh",
        "rm -rf \"$HOME/.ssh\"",
        "rm -rf $HOME/.ssh",
        "rm -rf ${HOME}/.ssh",
        "rm -rf \"${HOME}\"/.ssh",
        "rm -rf ~/.ssh",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/home/test/.ssh")
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn command_scoped_environment_assignments_do_not_leak() {
    for source in [
        "HOME=/tmp/example echo ok; rm -rf \"$HOME\"",
        "HOME=\"/tmp/example\" USERPROFILE=\"/tmp/example\" echo ok; rm -rf \"$HOME\"",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/home/test")
                        && effect.recursive
                        && effect.selects_home
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "HOME=/tmp/example; rm -rf \"$HOME\"",
        "tmpdir=/tmp/example; HOME=\"$tmpdir\" USERPROFILE=\"$tmpdir\" echo ok; rm -rf \"$tmpdir\"",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/tmp/example")
                        && effect.recursive
                        && !effect.selects_home
                        && !effect.selects_root
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source =
        "tmpdir=$(mktemp -d); HOME=\"$tmpdir\" USERPROFILE=\"$tmpdir\" echo ok; rm -rf \"$tmpdir\"";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), nah_proto::action::Coverage::Partial);
    assert!(
        !stream
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. })),
        "{source}: {:?}",
        stream.effects()
    );
}

#[test]
fn a_sequenced_directory_change_keeps_the_relative_effect() {
    // `;` runs the next statement even when `cd` failed, but forgetting the
    // directory it asked for would drop the delete entirely.
    for source in ["cd ~ && rm -rf .", "cd ~; rm -rf .", "cd ~\nrm -rf ."] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/home/test")
                        && effect.selects_home
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = "PWD=/; cd /does-not-exist; chmod -R 000 \"$PWD\"";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(
        stream.effects().iter().any(|effect| matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/")
                    && effect.recursive
        )),
        "{source}: {:?}",
        stream.effects()
    );
}

#[test]
fn rsync_delete_models_only_effectful_local_destinations() {
    for source in [
        "rsync --delete source/ /",
        "rsync --delete-before source/ /etc",
        "rsync -ah --delete-excluded host:source/ /",
        "rsync --delete source/ / --exclude pattern",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete && effect.recursive
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "rsync --dry-run --delete source/ /",
        "rsync -an --delete source/ /",
        "rsync --help --delete source/ /",
        "rsync --list-only --delete source/ /",
        "rsync --delete source/ host:/",
        "rsync --delete source/ host:/ --exclude pattern",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}
