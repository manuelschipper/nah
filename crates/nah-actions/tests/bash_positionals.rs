mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, FilesystemOperation};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn writes_critical(stream: &ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Write
                    && effect.target == absolute("/home/test/.nah/config")
        )
    })
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

fn refuses(stream: &ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation } if operation.as_str() == "analysis-refused"
        )
    })
}

#[test]
fn set_shift_and_positional_expansions_preserve_exact_targets() {
    for source in [
        r#"set -- /home/test/.nah/config; printf x > "$1""#,
        r#"set -- safe /home/test/.nah/config; shift; printf x > "$1""#,
        r#"set -- /home/test/.nah/config; printf x > "$*""#,
        r#"set -- ignored /home/test/.nah/config; shift 1; printf x > "${1}""#,
        r#"set -- /home/test/.nah/config; f(){ set -- safe; shift; }; f; printf x > "$1""#,
    ] {
        let actual = stream(source);
        assert!(writes_critical(&actual), "{source}: {:?}", actual.effects());
    }

    let branch = stream(
        r#"set -- safe; if test "$MODE" = x; then set -- /home/test/.nah/config; fi; printf x > "$1""#,
    );
    assert!(refuses(&branch), "{:?}", branch.effects());

    for source in [
        r#"set -- safe; shift 2; printf x > "$1""#,
        r#"set -- safe; shift -1; printf x > "$1""#,
        r#"set -- safe; f(){ set -- /home/test/.nah/config; }; f; printf x > "$1""#,
    ] {
        let actual = stream(source);
        assert!(
            !writes_critical(&actual),
            "{source}: {:?}",
            actual.effects()
        );
    }
}

#[test]
fn positional_command_expansion_distinguishes_quoted_and_unquoted_empty_fields() {
    let unquoted = stream("set -- '' rm -rf /; $@");
    assert!(deletes_root(&unquoted), "{:?}", unquoted.effects());

    let quoted = stream("set -- '' rm -rf /; \"$@\"");
    assert!(!deletes_root(&quoted), "{:?}", quoted.effects());

    let arguments = stream("set -- /home/test/.nah/config; touch $@");
    assert!(writes_critical(&arguments), "{:?}", arguments.effects());
}

#[test]
fn arithmetic_or_dynamic_shift_refuses_instead_of_preserving_a_false_exact_frame() {
    for source in [
        r#"set -- /home/test/.nah/config safe; n=1; shift n; printf x > "$1""#,
        r#"set -- /home/test/.nah/config safe; shift "$N"; printf x > "$1""#,
    ] {
        let actual = stream(source);
        assert!(refuses(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn child_command_arguments_initialize_zero_and_the_shiftable_frame() {
    for source in [
        r#"bash -c 'printf x > "$1"' shell /home/test/.nah/config"#,
        r#"bash -c 'printf x > "$0"' /home/test/.nah/config"#,
        r#"sh -c 'printf x > "$1"' shell /home/test/.nah/config"#,
        r#"bash -c 'f(){ shift; printf x > "$1"; }; f safe /home/test/.nah/config' shell"#,
    ] {
        let actual = stream(source);
        assert!(writes_critical(&actual), "{source}: {:?}", actual.effects());
    }

    let repeated = stream(
        r#"printf 'printf x > "$1"' > /tmp/script; bash /tmp/script safe; bash /tmp/script /home/test/.nah/config"#,
    );
    assert!(writes_critical(&repeated), "{:?}", repeated.effects());

    for source in [
        r#"bash -c 'printf x > "$1"' /home/test/.nah/config"#,
        r#"bash -c 'set -- safe; printf x > "$0"' shell"#,
    ] {
        let actual = stream(source);
        assert!(
            !writes_critical(&actual),
            "{source}: {:?}",
            actual.effects()
        );
    }
}

#[test]
fn optional_function_bindings_keep_both_function_and_external_lookup_paths() {
    for source in [
        "false && rm(){ :; }; rm -rf /",
        "rm(){ :; }; if false; then unset -f rm; fi; rm -rf /",
        "if false; then wipe(){ rm -rf /; }; fi; wipe",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn branch_merged_function_readonly_keeps_redefinition_and_unset_paths() {
    for source in [
        "f(){ :; }; if test \"$MODE\" = x; then readonly -f f; fi; f(){ rm -rf /; }; f",
        "f(){ rm -rf /; }; if test \"$MODE\" = x; then readonly -f f; fi; unset -f f; f",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}
