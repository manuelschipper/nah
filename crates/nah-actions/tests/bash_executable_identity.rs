mod support;

use nah_actions::finalize;
use nah_proto::action::{Coverage, EffectKind, InvocationEffect};
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed, PathKind,
    PathObservation,
};
use support::{Change, absolute, bash_plan, facts};

fn stream(
    source: &str,
    paths: &[(&str, &str, PathKind, Option<PathKind>)],
) -> nah_proto::action::ActionStream {
    let plan = bash_plan(source);
    let observation = Observation::new(
        SchemaVersion::V1,
        plan.observation_request().request_id(),
        facts(plan.observation_request(), "echo", Change::None)
            .into_iter()
            .map(|fact| {
                let ObservationQuery::Path { requested, .. } = fact.query() else {
                    return fact;
                };
                let Some((_, realpath, kind, target_kind)) =
                    paths.iter().find(|(candidate, ..)| candidate == requested)
                else {
                    return fact;
                };
                let mut path = PathObservation::new(
                    absolute(requested),
                    (requested != realpath).then(|| absolute(realpath)),
                    *kind,
                );
                if let Some(target_kind) = target_kind {
                    path = path.with_target_kind(*target_kind);
                }
                ObservationFact::new(
                    fact.query().clone(),
                    ObservationValue::Path {
                        observed: Observed::Ok { value: path },
                    },
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    finalize(plan, observation)
}

fn mutation(stream: &nah_proto::action::ActionStream) -> Option<&str> {
    stream
        .effects()
        .iter()
        .find_map(|effect| match effect.kind() {
            EffectKind::Invocation {
                invocation:
                    InvocationEffect::Known {
                        program,
                        operation,
                        input:
                            nah_proto::action::InvocationInput::Shell {
                                argv: Some(argv), ..
                            },
                        ..
                    },
            } if program == "nah"
                && argv.first().is_some_and(|program| program == "nah")
                && matches!(
                    operation.as_str(),
                    "critical-mutation" | "permanent-mutation"
                ) =>
            {
                Some(operation.as_str())
            }
            _ => None,
        })
}

fn tool_mutation(stream: &nah_proto::action::ActionStream, program: &str) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known {
                    program: actual,
                    operation,
                    ..
                }
            } if actual == program && operation.as_str() == "critical-mutation"
        )
    })
}

#[test]
fn observed_direct_nah_paths_retain_self_protection() {
    let installed = "/home/test/.local/bin/nah";
    for (source, paths, operation) in [
        (
            format!("{installed} trust /repo"),
            vec![(installed, installed, PathKind::File, None)],
            "critical-mutation",
        ),
        (
            "./alias trust /repo".into(),
            vec![(
                "/repo/alias",
                installed,
                PathKind::Symlink,
                Some(PathKind::File),
            )],
            "critical-mutation",
        ),
        (
            "./nah nap".into(),
            vec![("/repo/nah", "/repo/nah", PathKind::File, None)],
            "permanent-mutation",
        ),
    ] {
        let stream = stream(&source, &paths);
        assert_eq!(mutation(&stream), Some(operation), "{source}");
    }
}

#[test]
fn exact_same_call_file_aliases_retain_nah_identity() {
    let installed = "/home/test/.local/bin/nah";
    for command in ["cp", "cp -a", "ln", "ln -s", "link", "mv"] {
        let source = format!("{command} {installed} alias && ./alias trust /repo");
        let stream = stream(&source, &[(installed, installed, PathKind::File, None)]);
        assert_eq!(
            mutation(&stream),
            Some("critical-mutation"),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let chained = "cp /home/test/.local/bin/nah first; cp first second; ./second nap";
    let chained_stream = stream(
        chained,
        &[(
            "/home/test/.local/bin/nah",
            "/home/test/.local/bin/nah",
            PathKind::File,
            None,
        )],
    );
    assert_eq!(mutation(&chained_stream), Some("permanent-mutation"));

    for source in [
        "ln -s nah alias; ./alias trust /repo",
        "cp /home/test/.local/bin/nah first; ln -s first second; ./second trust /repo",
    ] {
        let stream = stream(
            source,
            &[
                ("/repo/nah", "/repo/nah", PathKind::File, None),
                (
                    "/home/test/.local/bin/nah",
                    "/home/test/.local/bin/nah",
                    PathKind::File,
                    None,
                ),
            ],
        );
        assert_eq!(
            mutation(&stream),
            Some("critical-mutation"),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn replacement_respects_destination_symlink_semantics() {
    let installed = "/home/test/.local/bin/nah";
    for source in [
        format!("mv ordinary alias; {installed} trust /repo"),
        format!("ln -f ordinary alias; {installed} trust /repo"),
    ] {
        let stream = stream(
            &source,
            &[
                (installed, installed, PathKind::File, None),
                ("/repo/ordinary", "/repo/ordinary", PathKind::File, None),
                (
                    "/repo/alias",
                    installed,
                    PathKind::Symlink,
                    Some(PathKind::File),
                ),
            ],
        );
        assert_eq!(
            mutation(&stream),
            Some("critical-mutation"),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = format!("cp ordinary alias; {installed} trust /repo");
    let stream = stream(
        &source,
        &[
            (installed, installed, PathKind::File, None),
            ("/repo/ordinary", "/repo/ordinary", PathKind::File, None),
            (
                "/repo/alias",
                installed,
                PathKind::Symlink,
                Some(PathKind::File),
            ),
        ],
    );
    assert_eq!(mutation(&stream), None, "{source}: {:?}", stream.effects());
}

#[test]
fn exact_replacements_of_existing_files_retain_nah_identity() {
    let installed = "/home/test/.local/bin/nah";
    for source in [
        format!("cp {installed} alias; ./alias trust /repo"),
        format!("cp -i {installed} alias; ./alias trust /repo"),
        format!("mv {installed} alias; ./alias trust /repo"),
        format!("ln -f {installed} alias; ./alias trust /repo"),
    ] {
        let stream = stream(
            &source,
            &[
                (installed, installed, PathKind::File, None),
                ("/repo/alias", "/repo/alias", PathKind::File, None),
            ],
        );
        assert_eq!(
            mutation(&stream),
            Some("critical-mutation"),
            "{source}: {:?}",
            stream.effects()
        );
        if source.starts_with("cp -i") {
            assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        }
    }

    let preserved = format!("cp {installed} alias; cp -n ordinary alias; ./alias trust /repo");
    let stream = stream(
        &preserved,
        &[
            (installed, installed, PathKind::File, None),
            ("/repo/ordinary", "/repo/ordinary", PathKind::File, None),
            ("/repo/alias", "/repo/alias", PathKind::File, None),
        ],
    );
    assert_eq!(mutation(&stream), Some("critical-mutation"));
}

#[test]
fn non_replacing_and_directory_forms_do_not_invent_identity() {
    let installed = "/home/test/.local/bin/nah";
    for (source, target_kind) in [
        (
            format!("cp -n {installed} alias; ./alias trust /repo"),
            PathKind::File,
        ),
        (
            format!("ln {installed} alias; ./alias trust /repo"),
            PathKind::File,
        ),
        (
            format!("link {installed} alias; ./alias trust /repo"),
            PathKind::File,
        ),
        (
            format!("cp {installed} alias; ./alias trust /repo"),
            PathKind::Directory,
        ),
        (
            format!("cp {installed} -t alias; ./alias trust /repo"),
            PathKind::Directory,
        ),
    ] {
        let stream = stream(
            &source,
            &[
                (installed, installed, PathKind::File, None),
                ("/repo/alias", "/repo/alias", target_kind, None),
            ],
        );
        assert_eq!(mutation(&stream), None, "{source}: {:?}", stream.effects());
    }

    let creates = format!("cp -n {installed} new; ./new trust /repo");
    let stream = stream(&creates, &[(installed, installed, PathKind::File, None)]);
    assert_eq!(mutation(&stream), Some("critical-mutation"));
}

#[test]
fn relative_symbolic_links_do_not_invent_executable_identity() {
    let installed = "/home/test/.local/bin/nah";
    for source in [
        "ln -s nah sub/alias; ./sub/alias trust /repo".to_owned(),
        "cp -s nah sub/alias; ./sub/alias trust /repo".to_owned(),
        "cp -P source-link alias; ./alias trust /repo".to_owned(),
        "ln -s missing alias; ./alias trust /repo".to_owned(),
        "ln -s ordinary alias; ./alias trust /repo".to_owned(),
    ] {
        let stream = stream(
            &source,
            &[
                ("/repo/nah", "/repo/nah", PathKind::File, None),
                (
                    "/repo/source-link",
                    installed,
                    PathKind::Symlink,
                    Some(PathKind::File),
                ),
                ("/repo/ordinary", "/repo/ordinary", PathKind::File, None),
            ],
        );
        assert_eq!(mutation(&stream), None, "{source}: {:?}", stream.effects());
    }
}

#[test]
fn delete_overwrite_and_replacement_clear_same_call_identity() {
    let installed = "/home/test/.local/bin/nah";
    for source in [
        format!("cp {installed} alias; printf x > alias; ./alias trust /repo"),
        format!("cp {installed} alias; rm alias; ./alias trust /repo"),
        format!("cp {installed} alias; cp ordinary alias; ./alias trust /repo"),
        format!("cp {installed} alias; mv ordinary alias; ./alias trust /repo"),
    ] {
        let stream = stream(
            &source,
            &[
                (installed, installed, PathKind::File, None),
                ("/repo/ordinary", "/repo/ordinary", PathKind::File, None),
            ],
        );
        assert_eq!(mutation(&stream), None, "{source}: {:?}", stream.effects());
    }
}

#[test]
fn conditional_mutations_preserve_possible_nah_identity() {
    let installed = "/home/test/.local/bin/nah";
    for source in [
        format!("cp {installed} alias; false && cp ordinary alias; ./alias trust /repo"),
        format!("cp {installed} alias; false && rm alias; ./alias trust /repo"),
        format!("cp {installed} alias || cp ordinary alias; ./alias trust /repo"),
        format!("false && cp {installed} alias; ./alias trust /repo"),
    ] {
        let stream = stream(
            &source,
            &[
                (installed, installed, PathKind::File, None),
                ("/repo/ordinary", "/repo/ordinary", PathKind::File, None),
            ],
        );
        assert_eq!(
            mutation(&stream),
            Some("critical-mutation"),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn executable_lookalikes_and_non_mutations_do_not_gain_nah_identity() {
    let installed = "/home/test/.local/bin/nah";
    for (source, paths) in [
        (
            "./not-nah trust /repo",
            vec![("/repo/not-nah", "/repo/not-nah", PathKind::File, None)],
        ),
        (
            "./copied-alias trust /repo",
            vec![(
                "/repo/copied-alias",
                "/repo/copied-alias",
                PathKind::File,
                None,
            )],
        ),
        (
            "./alias docs extending",
            vec![(
                "/repo/alias",
                installed,
                PathKind::Symlink,
                Some(PathKind::File),
            )],
        ),
        (
            "cp /repo/nah.txt alias; ./alias trust /repo",
            vec![("/repo/nah.txt", "/repo/nah.txt", PathKind::File, None)],
        ),
    ] {
        let stream = stream(source, &paths);
        assert_eq!(mutation(&stream), None, "{source}: {:?}", stream.effects());
    }
}

#[test]
fn exact_standard_rm_copies_retain_only_their_observed_identity() {
    let paths = [("/bin/rm", "/usr/bin/rm", PathKind::File, None)];
    for source in [
        "cp /bin/rm /tmp/not-rm; /tmp/not-rm -rf /home/test/.nah",
        "cp /bin/rm /tmp/first; cp /tmp/first /tmp/second; /tmp/second /home/test/.nah/trust.json",
    ] {
        let stream = stream(source, &paths);
        assert!(
            tool_mutation(&stream, "rm"),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "cp /bin/rm /tmp/not-rm; /tmp/not-rm --help /home/test/.nah",
        "cp /bin/rm /tmp/not-rm; /tmp/not-rm -rf /tmp/ordinary",
    ] {
        let stream = stream(source, &paths);
        assert!(
            !tool_mutation(&stream, "rm"),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let lookalike = stream(
        "cp /repo/rm /tmp/not-rm; /tmp/not-rm -rf /home/test/.nah",
        &[("/repo/rm", "/repo/rm", PathKind::File, None)],
    );
    assert!(!tool_mutation(&lookalike, "rm"));
}
