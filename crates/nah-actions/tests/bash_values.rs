mod support;

use nah_actions::finalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect};
use nah_proto::observation::ObservationQuery;
use support::{absolute, bash_plan, observe};

fn lower(source: &str) -> nah_proto::action::ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn has_filesystem(
    stream: &nah_proto::action::ActionStream,
    operation: FilesystemOperation,
    target: &str,
) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == operation && effect.target == absolute(target)
        )
    })
}

fn has_unresolved_command(stream: &nah_proto::action::ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::CodeExecution { source, .. }
            } if source.as_str() == "unresolved-command"
        )
    })
}

#[test]
fn local_values_reach_programs_operands_redirects_git_and_self_protection() {
    for source in [
        "TOOL=rm; \"$TOOL\" -rf /",
        "declare TOOL=rm; \"$TOOL\" -rf /",
        "TOOL=rm; export TOOL; \"$TOOL\" -rf /",
        "TOOL=rm; readonly TOOL; \"$TOOL\" -rf /",
        "TOOL=rm; declare TOOL; \"$TOOL\" -rf /",
        "TOOL=$(printf rm); \"$TOOL\" -rf /",
        "$(printf rm) -rf /",
        "$(printf r)m -rf /",
        "P=/; rm -rf \"$P\"",
        "f(){ rm -rf /; }; F=f; \"$F\"",
    ] {
        let stream = lower(source);
        assert!(
            has_filesystem(&stream, FilesystemOperation::Delete, "/"),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let stream = lower("P=/; rm -rf \"${P}etc\"");
    assert!(has_filesystem(&stream, FilesystemOperation::Delete, "/etc"));

    let stream = lower("rm -rf \"$(printf /)\"");
    assert!(has_filesystem(&stream, FilesystemOperation::Delete, "/"));

    for source in [
        "F=/home/test/.nah/config; printf x > \"$F\"",
        "F=$(printf /home/test/.nah/config); printf x > \"$F\"",
        "F=/home/test/.nah/config; { printf x; } > \"$F\"",
        "F=/home/test/.nah/config; > \"$F\"",
    ] {
        let stream = lower(source);
        assert!(
            has_filesystem(
                &stream,
                FilesystemOperation::Write,
                "/home/test/.nah/config"
            ),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let stream = lower("OP=reset; git \"$OP\" --hard");
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "hard-reset")
    }));

    let stream = lower("ACTION=trust; nah \"$ACTION\" /repo");
    assert!(stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. }
            } if operation.as_str() == "critical-mutation"
        )
    }));
}

#[test]
fn unset_unknown_overwrite_and_splitting_never_reuse_a_stale_value() {
    for source in [
        "TOOL=rm; unset TOOL; \"$TOOL\" -rf /",
        "TOOL=rm; TOOL=\"$UNKNOWN\"; \"$TOOL\" -rf /",
        "TOOL=rm; if test -e marker; then TOOL=safe; fi; \"$TOOL\" -rf /",
        "TOOL='rm echo'; $TOOL -rf /",
        "TOOL='r*'; $TOOL -rf /",
    ] {
        let stream = lower(source);
        assert!(
            !has_filesystem(&stream, FilesystemOperation::Delete, "/"),
            "{source}: {:?}",
            stream.effects()
        );
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::CodeExecution { source, .. }
                } if matches!(source.as_str(), "unresolved-command" | "shell-pattern")
            )
        }));
    }

    let stream = lower("P=/; P=safe; rm -rf \"$P\"");
    assert!(!has_filesystem(&stream, FilesystemOperation::Delete, "/"));
    assert!(has_filesystem(
        &stream,
        FilesystemOperation::Delete,
        "/repo/safe"
    ));

    let stream = lower("P=/; unset P; rm -rf \"$P\"");
    assert!(!stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
        )
    }));

    let plan = bash_plan("unset TOOL; \"$TOOL\" -rf /");
    assert!(
        !plan
            .observation_request()
            .queries()
            .iter()
            .any(|query| matches!(query, ObservationQuery::Env { name, .. } if name == "TOOL"))
    );
}

#[test]
fn unresolved_destructive_operands_do_not_invent_filesystem_targets() {
    for source in [
        "rm -rf \"$(unknown)\"",
        "chmod -R 000 \"$(unknown)\"",
        "chmod -R --reference=ref \"$UNKNOWN\"",
        "chown -R --reference ref \"$UNKNOWN\"",
        "setfacl -R -m u::r \"$UNKNOWN\"",
        "unknown(){ printf ../../../../../../etc; }; rm -rf safe/$(unknown)",
    ] {
        let stream = lower(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. })),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let stream = lower("P=safe; read P <<< ../../../../../../etc; rm -rf \"safe/$P\"");
    assert!(stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.target == absolute("/etc")
                    && effect.operation == FilesystemOperation::Delete
                    && effect.recursive
        )
    }));

    let stream = lower("P='/*'; rm -rf $P");
    assert!(stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.target == absolute("/*") && effect.pattern && effect.recursive
        )
    }));

    for source in [
        "chmod \"$(printf 755)\" safe",
        "setfacl -R -m \"$UNKNOWN\" safe",
    ] {
        let stream = lower(source);
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.target == absolute("/*") && effect.pattern
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn custom_ifs_and_mixed_chains_cannot_hide_split_commands() {
    for source in [
        "IFS=:; TOOL='rm:-rf:/'; $TOOL",
        "TOOL=echo; true && TOOL=rm || TOOL=echo; \"$TOOL\" -rf /",
    ] {
        let stream = lower(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            has_unresolved_command(&stream),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn declaration_rhs_values_use_the_pre_declaration_snapshot() {
    for declaration in ["export", "declare", "readonly", "typeset"] {
        let source = format!("A=rm; {declaration} A=echo B=$A; \"$B\" -rf /");
        let stream = lower(&source);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(
            has_filesystem(&stream, FilesystemOperation::Delete, "/"),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn ordinary_variable_references_do_not_imply_descriptor_uncertainty() {
    for source in ["A=rm; true", "A=rm; B=$A; printf '%s' \"$B\""] {
        let stream = lower(source);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(stream.effects().iter().all(|effect| {
            !matches!(
                effect.kind(),
                EffectKind::SystemState { operation } if operation.as_str() == "analysis-refused"
            )
        }));
    }
}

#[test]
fn namerefs_and_unmodeled_declaration_transformations_fail_closed() {
    for source in [
        "TARGET=rm; declare -n TOOL=TARGET; \"$TOOL\" -rf /",
        "declare -l TOOL=RM; \"$TOOL\" -rf /",
        "declare -u TOOL=rm; \"$TOOL\" -rf /",
        "declare -i TOOL=1+1; \"$TOOL\" -rf /",
        "declare -a TOOL=rm; \"$TOOL\" -rf /",
        "declare -A TOOL=rm; \"$TOOL\" -rf /",
        "declare TOOL={echo,rm}; \"$TOOL\" -rf /",
        "typeset -l TOOL=RM; \"$TOOL\" -rf /",
    ] {
        let stream = lower(source);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            has_unresolved_command(&stream),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn function_local_bindings_do_not_leak_into_the_caller() {
    let source = "TOOL=rm; f(){ local TOOL=echo; }; f; \"$TOOL\" -rf /";
    let stream = lower(source);
    assert!(
        has_filesystem(&stream, FilesystemOperation::Delete, "/"),
        "{:?}",
        stream.effects()
    );
}
