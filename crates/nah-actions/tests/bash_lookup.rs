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

fn refuses(stream: &ActionStream) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation } if operation.as_str() == "analysis-refused"
        )
    })
}

#[test]
fn hashes_and_builtin_enablement_select_the_executable_identity() {
    for source in [
        "hash -p /bin/rm wipe; wipe -rf /",
        "hash -p /bin/rm echo; enable -n echo; echo -rf /",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        "hash -p /bin/rm echo; echo -rf /",
        "hash -p /bin/rm echo; enable -n echo; enable -s echo; echo -rf /",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn command_and_builtin_apply_their_real_lookup_boundaries() {
    let normal = stream("f(){ rm -rf /; }; f");
    assert!(deletes_root(&normal), "{:?}", normal.effects());

    for source in [
        "f(){ rm -rf /; }; command f",
        "f(){ rm -rf /; }; command -p f",
        "f(){ rm -rf /; }; builtin f",
        "hash -p /bin/rm wipe; command -p wipe -rf /",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    let hashed = stream("hash -p /bin/rm wipe; command wipe -rf /");
    assert!(deletes_root(&hashed), "{:?}", hashed.effects());

    let alias_suppressed = stream(
        "shopt -s expand_aliases\nalias wipe='echo safe'\nhash -p /bin/rm wipe\ncommand wipe -rf /",
    );
    assert!(
        deletes_root(&alias_suppressed),
        "{:?}",
        alias_suppressed.effects()
    );

    let external_wrapper = stream("hash -p /bin/echo rm; sudo rm -rf /");
    assert!(
        deletes_root(&external_wrapper),
        "{:?}",
        external_wrapper.effects()
    );
}

#[test]
fn accepted_path_changes_clear_hashes_but_rejected_readonly_changes_do_not() {
    for source in [
        "hash -p /bin/rm wipe; PATH=/bin wipe -rf /",
        "hash -p /bin/rm wipe; PATH=/bin true; wipe -rf /",
        "hash -p /bin/rm wipe; PATH=/bin; wipe -rf /",
        "hash -p /bin/rm wipe; unset PATH; wipe -rf /",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    let rejected = stream("hash -p /bin/rm wipe; readonly PATH; PATH=/bin wipe -rf /");
    assert!(deletes_root(&rejected), "{:?}", rejected.effects());
}

#[test]
fn command_not_found_handler_is_reachable_only_from_a_bare_path_miss() {
    let bare = stream("definitely_missing");
    assert!(!refuses(&bare), "{:?}", bare.effects());

    let handler = "command_not_found_handle(){ rm -rf /; };";
    for source in [
        format!("{handler} missing"),
        format!("{handler} command missing"),
        format!("{handler} command -p missing"),
    ] {
        let actual = stream(&source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
        assert!(!refuses(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        format!("{handler} echo"),
        format!("{handler} builtin missing"),
        format!("{handler} ./missing"),
        format!("{handler} hash -p /bin/echo missing; missing"),
    ] {
        let actual = stream(&source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn command_not_found_handler_state_does_not_escape_its_subshell() {
    let source =
        r#"TOOL=echo; command_not_found_handle(){ TOOL=rm; cd /; }; missing; "$TOOL" -rf /"#;
    let actual = stream(source);
    assert!(!deletes_root(&actual), "{:?}", actual.effects());
}

#[test]
fn exhaustive_lookup_branches_are_lowered_and_unknown_targets_refuse() {
    let branches = stream(
        "if test \"$MODE\" = dangerous; then hash -p /bin/rm wipe; else hash -p /bin/echo wipe; fi; wipe -rf /",
    );
    assert!(deletes_root(&branches), "{:?}", branches.effects());
    assert!(!refuses(&branches), "{:?}", branches.effects());

    let unknown = stream("hash \"$UNKNOWN\"; wipe -rf /");
    assert!(refuses(&unknown), "{:?}", unknown.effects());
}

#[test]
fn aliases_use_parse_unit_snapshots_and_expand_recursively() {
    for source in [
        "shopt -s expand_aliases\nalias wipe='rm -rf /'\nwipe",
        "shopt -s expand_aliases\nalias first=second\nalias second='rm -rf /'\nfirst",
        "shopt -s expand_aliases\nalias outer='eval '\nalias payload='rm -rf /'\nouter payload",
        "shopt -s expand_aliases\nalias lead='command '\nalias wipe='rm -rf /'\nlead wipe",
    ] {
        let actual = stream(source);
        assert!(deletes_root(&actual), "{source}: {:?}", actual.effects());
    }

    for source in [
        "shopt -s expand_aliases\nalias wipe='rm -rf /'; wipe",
        "shopt -s expand_aliases\nalias wipe='rm -rf /'\n'wipe'",
        "shopt -s expand_aliases\nalias wipe='rm -rf /'\ncommand wipe",
        "shopt -s expand_aliases\nalias wipe='rm -rf /'\nbuiltin wipe",
        "shopt -s expand_aliases\nalias wipe='rm -rf /'\nalias wipe=wipe\nwipe",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn function_and_compound_aliases_are_frozen_when_bash_parses_them() {
    let function = stream(
        "shopt -s expand_aliases\nalias wipe='rm -rf /'\nf(){ wipe; }\nalias wipe='echo safe'\nf",
    );
    assert!(deletes_root(&function), "{:?}", function.effects());

    for source in [
        "shopt -s expand_aliases\n{ alias wipe='rm -rf /'; wipe; }",
        "shopt -s expand_aliases\necho \"$(alias wipe='rm -rf /'; wipe)\"",
    ] {
        let actual = stream(source);
        assert!(!deletes_root(&actual), "{source}: {:?}", actual.effects());
    }
}

#[test]
fn exact_alias_branch_unions_preserve_every_reachable_target() {
    let source = "shopt -s expand_aliases\nif test \"$MODE\" = dangerous; then alias wipe='rm -rf /'; else alias wipe='echo safe'; fi\nwipe";
    let actual = stream(source);
    assert!(deletes_root(&actual), "{:?}", actual.effects());
    assert!(!refuses(&actual), "{:?}", actual.effects());
}
