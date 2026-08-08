mod support;

use nah_actions::finalize;
use nah_parse::normalize;
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, InvocationEffect, SemanticCode,
};
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    Observation, ObservationFact, ObservationFailure, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathKind, PathObservation,
};
use support::{absolute, bash_plan, observe};

#[derive(Clone, Copy, Debug)]
enum DestinationObservation {
    Path(PathKind, Option<PathKind>),
    RootSymlink,
    Error(ObservationFailure),
}

fn observe_destinations(
    request: &ObservationRequest,
    destinations: &[(&str, DestinationObservation)],
) -> Observation {
    let facts = support::facts(request, "echo", support::Change::None)
        .into_iter()
        .map(|fact| {
            let destination = match fact.query() {
                ObservationQuery::Path { requested, .. } => {
                    destinations.iter().find_map(|(target, observation)| {
                        (requested == target).then_some(*observation)
                    })
                }
                _ => None,
            };
            let Some(destination) = destination else {
                return fact;
            };
            let observed = match destination {
                DestinationObservation::Path(kind, target_kind) => {
                    let mut path = PathObservation::new(
                        match fact.query() {
                            ObservationQuery::Path { requested, .. } => absolute(requested),
                            _ => unreachable!(),
                        },
                        None,
                        kind,
                    );
                    if let Some(target_kind) = target_kind {
                        path = path.with_target_kind(target_kind);
                    }
                    Observed::Ok { value: path }
                }
                DestinationObservation::RootSymlink => Observed::Ok {
                    value: PathObservation::new(
                        match fact.query() {
                            ObservationQuery::Path { requested, .. } => absolute(requested),
                            _ => unreachable!(),
                        },
                        Some(absolute("/")),
                        PathKind::Symlink,
                    )
                    .with_target_kind(PathKind::Directory),
                },
                DestinationObservation::Error(error) => Observed::Error { error },
            };
            ObservationFact::new(fact.query().clone(), ObservationValue::Path { observed }).unwrap()
        })
        .collect();
    Observation::new(SchemaVersion::V1, request.request_id(), facts).unwrap()
}

fn has_known_move(stream: &nah_proto::action::ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known {
                    operation,
                    ..
                }
            } if operation == &SemanticCode::MOVE
        )
    })
}

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

#[test]
fn root_pattern_moves_become_known_only_with_a_proven_directory_destination() {
    for source in [
        "mv /* /tmp",
        "mv -- /* /tmp",
        "mv -t /tmp /*",
        "mv --target-directory /tmp /*",
        "mv --target-directory=/tmp /*",
        "/bin/mv /* /tmp",
        "/usr/bin/mv /* /tmp",
    ] {
        let plan = bash_plan(source);
        let observation = observe_destinations(
            plan.observation_request(),
            &[(
                "/tmp",
                DestinationObservation::Path(PathKind::Directory, None),
            )],
        );
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(has_known_move(&stream), "{source}: {stream:?}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == absolute("/*")
                    && effect.pattern
                    && !effect.recursive)
        }));
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/tmp"))
        }));
    }

    let plan = bash_plan("mv /* /tmp");
    let observation = observe_destinations(
        plan.observation_request(),
        &[(
            "/tmp",
            DestinationObservation::Path(PathKind::Symlink, Some(PathKind::Directory)),
        )],
    );
    assert!(has_known_move(&finalize(plan, observation)));
}

#[test]
fn root_pattern_move_promotion_rejects_uncertain_grammars_and_destinations() {
    for destination in [
        DestinationObservation::Path(PathKind::Missing, None),
        DestinationObservation::Path(PathKind::File, None),
        DestinationObservation::Path(PathKind::Fifo, None),
        DestinationObservation::Path(PathKind::Other, None),
        DestinationObservation::Path(PathKind::Symlink, Some(PathKind::File)),
        DestinationObservation::Error(ObservationFailure::PermissionDenied),
        DestinationObservation::Error(ObservationFailure::Timeout),
        DestinationObservation::Error(ObservationFailure::Unavailable),
    ] {
        let plan = bash_plan("mv /* /tmp");
        let observation =
            observe_destinations(plan.observation_request(), &[("/tmp", destination)]);
        let stream = finalize(plan, observation);
        assert!(!has_known_move(&stream), "{destination:?}: {stream:?}");
    }

    for source in [
        "mv -T /* /tmp",
        "mv -n /* /tmp",
        "mv -f /* /tmp",
        "mv -i /* /tmp",
        "mv -u /* /tmp",
        "mv -t/tmp /*",
        "mv /* -t/tmp",
        "mv /* --target-directory=/tmp",
        "mv /* /tmp extra",
        "mv '/*' /tmp",
        r"mv /\* /tmp",
        "mv * /tmp",
        "mv /*/ /tmp",
        "mv /{bin,etc} /tmp",
        "mv /[a-z]* /tmp",
        "mv /home/test/* /tmp",
        "mv project/* /tmp",
        r#"mv /* "$DEST""#,
    ] {
        let plan = bash_plan(source);
        let observation = observe_destinations(
            plan.observation_request(),
            &[(
                "/tmp",
                DestinationObservation::Path(PathKind::Directory, None),
            )],
        );
        let stream = finalize(plan, observation);
        assert!(!has_known_move(&stream), "{source}: {stream:?}");
    }

    for (source, target, destination) in [
        (
            "mv /* /",
            "/",
            DestinationObservation::Path(PathKind::Directory, None),
        ),
        (
            "mv /* /root-link",
            "/root-link",
            DestinationObservation::RootSymlink,
        ),
    ] {
        let plan = bash_plan(source);
        let observation =
            observe_destinations(plan.observation_request(), &[(target, destination)]);
        let stream = finalize(plan, observation);
        assert!(!has_known_move(&stream), "{source}: {stream:?}");
    }
}

#[test]
fn root_move_destination_binding_ignores_redirect_writes() {
    let plan = bash_plan("mv /* /tmp > /directory-looking");
    let observation = observe_destinations(
        plan.observation_request(),
        &[
            (
                "/directory-looking",
                DestinationObservation::Path(PathKind::Directory, None),
            ),
            ("/tmp", DestinationObservation::Path(PathKind::File, None)),
        ],
    );
    let stream = finalize(plan, observation);
    assert!(!has_known_move(&stream), "{stream:?}");
}
