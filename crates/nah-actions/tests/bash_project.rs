mod support;

use nah_actions::finalize;
use nah_parse::normalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect};
use support::{absolute, bash_plan, observe};

#[test]
fn project_lowering_emits_complete_copy_move_create_and_delete_effects() {
    for (source, program, operation, expected) in [
        (
            "cp src/lib.rs copied.rs",
            "cp",
            "copy",
            vec![
                (FilesystemOperation::Read, "/repo/src/lib.rs"),
                (FilesystemOperation::Write, "/repo/copied.rs"),
            ],
        ),
        (
            "mv old.txt moved.txt",
            "mv",
            "move",
            vec![
                (FilesystemOperation::Delete, "/repo/old.txt"),
                (FilesystemOperation::Write, "/repo/moved.txt"),
            ],
        ),
        (
            "cp -R -t copied src/lib.rs",
            "cp",
            "copy",
            vec![
                (FilesystemOperation::Read, "/repo/src/lib.rs"),
                (FilesystemOperation::Write, "/repo/copied"),
            ],
        ),
        (
            "mv --target-directory=moved old.txt",
            "mv",
            "move",
            vec![
                (FilesystemOperation::Delete, "/repo/old.txt"),
                (FilesystemOperation::Write, "/repo/moved"),
            ],
        ),
        (
            "mv -t moved old.txt",
            "mv",
            "move",
            vec![
                (FilesystemOperation::Delete, "/repo/old.txt"),
                (FilesystemOperation::Write, "/repo/moved"),
            ],
        ),
        (
            "rm -rf build/output",
            "rm",
            "remove",
            vec![(FilesystemOperation::Delete, "/repo/build/output")],
        ),
        (
            "mkdir -p generated",
            "mkdir",
            "create",
            vec![(FilesystemOperation::Write, "/repo/generated")],
        ),
        (
            "touch generated.txt",
            "touch",
            "update",
            vec![(FilesystemOperation::Write, "/repo/generated.txt")],
        ),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(matches!(
            stream.effects()[0].kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known {
                    program: actual,
                    operation: actual_operation,
                    ..
                }
            } if actual == program && actual_operation.as_str() == operation
        ));
        let actual = stream
            .effects()
            .iter()
            .filter_map(|effect| match effect.kind() {
                EffectKind::Filesystem { effect } => {
                    Some((effect.operation, effect.target.as_str()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            expected
                .iter()
                .map(|(operation, target)| (*operation, *target))
                .collect::<Vec<_>>(),
            "{source}"
        );
    }
}

#[test]
fn project_lowering_fails_closed_without_losing_static_effects() {
    for source in [
        "cp --definitely-unknown src/lib.rs copied.rs",
        "cp src/lib.rs \"$OUT\"",
        "mv only-one-operand",
        "rm \"$TARGET\"",
        "rmdir -p child/grandchild",
        "touch --definitely-unknown generated.txt",
        "cp src/lib.rs copied.rs --help",
        "rm {build,.env}",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        assert_eq!(
            finalize(plan, observation).coverage(),
            Coverage::Partial,
            "{source}"
        );
    }

    let plan = bash_plan("cp src/lib.rs \"$OUT\"");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Read
                && effect.target == absolute("/repo/src/lib.rs"))
    }));

    let plan = bash_plan("rm -rf .");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Delete && effect.selects_root)
    }));

    let plan = bash_plan("rm -rf / --help");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(
        !stream
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. }))
    );

    for source in [
        "cp -- src/lib.rs copied.rs",
        "cp -r src generated",
        "rm -- .",
        "unlink -- old.txt",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        assert_eq!(
            finalize(plan, observation).coverage(),
            Coverage::Full,
            "{source}"
        );
    }

    for source in ["rm -- -r", "rmdir -- --parents"] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect } if !effect.recursive)
        }));
    }

    let plan = bash_plan("rm --help /");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(
        !stream
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. }))
    );
}

#[test]
fn redirect_capabilities_are_not_lost() {
    for (source, coverage, operations) in [
        ("cat < in", Coverage::Full, vec![FilesystemOperation::Read]),
        (
            "echo hi >& out",
            Coverage::Full,
            vec![FilesystemOperation::Write],
        ),
        (
            "tool <> data",
            Coverage::Partial,
            vec![FilesystemOperation::Read, FilesystemOperation::Write],
        ),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(
            stream.coverage(),
            coverage,
            "{source}: {:?}",
            normalize(source).unwrap()
        );
        let actual = stream
            .effects()
            .iter()
            .filter_map(|effect| match effect.kind() {
                EffectKind::Filesystem { effect } => Some(effect.operation),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, operations, "{source}");
    }
}
