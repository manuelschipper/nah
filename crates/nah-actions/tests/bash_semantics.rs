mod support;

use nah_actions::finalize;
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, InvocationEffect, InvocationInput,
};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> nah_proto::action::ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

#[test]
fn standard_program_paths_and_unambiguous_options_keep_permission_semantics() {
    for source in [
        "/bin/chmod --rec 000 /",
        "/usr/bin/chown --rec root /",
        "/usr/bin/chgrp --rec root /",
        "/usr/bin/setfacl --rec -m u:test:r /",
        "command /usr/bin/chmod --rec 000 /",
        "env /usr/bin/chmod --rec 000 /",
        "busybox chmod --rec 000 /",
    ] {
        let stream = stream(source);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.operation == FilesystemOperation::Write
                            && effect.target == absolute("/")
                            && effect.recursive
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn executable_lookalikes_and_ambiguous_options_do_not_gain_system_semantics() {
    for source in [
        "/tmp/chmod --rec 000 /",
        "/usr/local/bin/chmod --rec 000 /",
        "./chmod --rec 000 /",
    ] {
        let stream = stream(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.target == absolute("/")
                            && effect.operation == FilesystemOperation::Write
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::CodeExecution { source, .. }
                } if source.as_str() == "direct-file"
            )
        }));
    }

    let ambiguous = stream("chmod --re 000 /");
    assert!(!ambiguous.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect } if effect.recursive
        )
    }));
}

#[test]
fn git_abbreviations_are_canonical_only_for_semantic_lowering() {
    for (source, operation) in [
        ("git reset --h", "hard-reset"),
        ("git gc --p=now", "recovery-destroy"),
        ("git prune --exp=now", "recovery-destroy"),
        ("git reflog expire --expire-=now --a", "recovery-destroy"),
        ("git push --force-w=other origin +main", "force-push"),
    ] {
        let stream = stream(source);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Git { operation: actual } if actual.as_str() == operation
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let qualified = stream("/usr/bin/git reset --h");
    let invocation = qualified
        .effects()
        .iter()
        .find_map(|effect| match effect.kind() {
            EffectKind::Invocation { invocation } => Some(invocation),
            _ => None,
        })
        .expect("invocation");
    assert!(matches!(
        invocation.input(),
        InvocationInput::Shell { argv: Some(argv), .. }
            if argv == &["/usr/bin/git", "reset", "--h"]
    ));

    let invalid_global_abbreviation = stream("git --git-d=/tmp reset --h");
    assert!(
        !invalid_global_abbreviation
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Git { .. }))
    );
    for source in [
        "git prune --d --exp=now",
        "git reflog expire --d --a --expire=now",
        "git push --dr --force origin main",
    ] {
        assert!(
            !stream(source)
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Git { .. })),
            "{source}"
        );
    }
}

#[test]
fn cwd_aliases_resolve_only_from_exact_shell_state() {
    for (source, target) in [
        ("chmod -R 000 ~+", "/repo"),
        ("chmod -R 000 \"$PWD\"", "/repo"),
        ("chmod -R 000 ~test", "/home/test"),
        (
            "PWD=/home/test; chmod -R 000 \"$PWD/.config\"",
            "/home/test/.config",
        ),
    ] {
        let stream = stream(source);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.target == absolute(target) && effect.recursive
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = "chmod -R 000 ~someone-else";
    let actual = stream(source);
    assert_eq!(actual.coverage(), Coverage::Partial, "{source}");
    assert!(
        !actual
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. })),
        "{source}: {:?}",
        actual.effects()
    );

    let source = "PWD=\"$UNKNOWN\"; chmod -R 000 \"$PWD/private\"";
    let actual = stream(source);
    assert_eq!(actual.coverage(), Coverage::Partial);
    assert!(
        !actual
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. }))
    );
}
