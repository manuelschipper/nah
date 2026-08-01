mod support;

use nah_actions::finalize;
use nah_proto::action::{EffectKind, FilesystemOperation, InvocationEffect, Sensitivity};
use support::{absolute, bash_plan, observe};

#[test]
fn static_bindings_and_nested_executors_preserve_guard_evidence() {
    for source in [
        "eval 'rm -rf /'",
        "xargs rm -rf /",
        "find /tmp -exec rm -rf / '{}' \\;",
        "find /tmp -execdir rm -rf / '{}' +",
        "find / -exec rm -rf '{}' +",
        "CMD=rm TARGET=/; \"$CMD\" -rf \"$TARGET\"",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
                        && effect.target == absolute("/")
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = "find / -exec chmod -R 000 '{}' +";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target == absolute("/")
                && effect.recursive
    )));

    for (source, expected) in [
        ("find /tmp -ok cat ~/.ssh/id_rsa \\;", "credential-secret"),
        ("find /tmp -okdir nah trust /repo \\;", "critical-mutation"),
        (
            "CMD=cat TARGET=~/.ssh/id_rsa; \"$CMD\" \"$TARGET\"",
            "credential-secret",
        ),
        ("CMD=nah; \"$CMD\" trust /repo", "critical-mutation"),
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| match effect.kind() {
                EffectKind::Filesystem { effect } => {
                    expected == "credential-secret"
                        && effect.sensitivity == Sensitivity::CredentialSecret
                }
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. },
                } => operation.as_str() == expected,
                _ => false,
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn dynamic_malformed_and_relative_execdir_forms_remain_unlowered() {
    for source in [
        "eval \"$PAYLOAD\"",
        "printf 'rm -rf /' | xargs \"$CMD\"",
        "find /tmp -exec rm -rf / '{}'",
        "find /tmp -execdir rm -rf . '{}' \\;",
        "find /tmp -exec rm -rf '{}' +",
        "CMD=$(cat /tmp/tool); \"$CMD\" -rf /",
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

    let source = "find /tmp -exec chmod -R 000 '{}' +";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(!stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target == absolute("/")
                && effect.recursive
    )));
}

#[test]
fn deterministic_command_substitution_resolves_nested_programs() {
    let source = "CMD=$(printf rm); \"$CMD\" -rf /";
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

#[test]
fn find_selector_scope_marks_only_the_substituted_permission_target_recursive() {
    for (source, target) in [
        ("find / -exec chmod 000 '{}' +", "/"),
        ("find / -exec chown root '{}' +", "/"),
        ("find / -exec chgrp root '{}' +", "/"),
        ("find / -exec setfacl -b '{}' +", "/"),
        ("find ~ -exec chmod 000 '{}' +", "/home/test"),
        ("find /repo -exec chmod 000 '{}' +", "/repo"),
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Write
                        && effect.target == absolute(target)
                        && effect.recursive
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let source = "find / -maxdepth 0 -exec chmod 000 '{}' +";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(
        stream.effects().iter().all(|effect| !matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/")
                    && effect.recursive
        )),
        "{source}: {:?}",
        stream.effects()
    );

    let source = "find / -exec chmod 000 /tmp/fixed '{}' +";
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(
        stream.effects().iter().all(|effect| !matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/tmp/fixed")
                    && effect.recursive
        )),
        "{source}: {:?}",
        stream.effects()
    );
}
