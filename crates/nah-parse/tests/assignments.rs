use nah_parse::{Statement, normalize};

#[test]
fn literal_shell_assignments_are_owned_syntax() {
    let syntax = normalize("CMD=rm TARGET=/; \"$CMD\" -rf \"$TARGET\"").unwrap();
    assert!(syntax.complete());
    assert!(matches!(
        &syntax.statements()[0],
        Statement::Assignments { bindings, .. }
            if bindings.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>()
                == ["CMD", "TARGET"]
    ));
}

#[test]
fn compound_assignment_forms_remain_incomplete() {
    for source in ["ITEMS=(one two)", "ITEMS[0]=one", "ITEMS+=two"] {
        let syntax = normalize(source).unwrap();
        assert!(!syntax.complete(), "{source}: {syntax:?}");
    }
}

#[test]
fn erased_assignments_preserve_raw_words_and_modeled_source_order() {
    let syntax = normalize(r#"FIRST=one ITEMS["${target:=0}"]=value LAST="$FIRST""#).unwrap();
    let [
        Statement::Assignments {
            bindings,
            unmodeled,
        },
    ] = syntax.statements()
    else {
        panic!("unexpected syntax: {syntax:?}");
    };
    assert_eq!(
        bindings
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["FIRST", "LAST"]
    );
    assert_eq!(unmodeled.len(), 1);
    assert_eq!(unmodeled[0].preceding_bindings(), 1);
    assert!(unmodeled[0].mutates_current_shell());
    assert_eq!(unmodeled[0].word().raw(), r#"ITEMS["${target:=0}"]=value"#);
}

#[test]
fn prefix_and_declaration_assignments_retain_their_state_scope() {
    let prefix = normalize(r#"FIRST=one ITEMS["${target:=0}"]=value env"#).unwrap();
    let [
        Statement::Command {
            assignments,
            unmodeled_assignments,
            ..
        },
    ] = prefix.statements()
    else {
        panic!("unexpected prefix syntax: {prefix:?}");
    };
    assert_eq!(assignments[0].0, "FIRST");
    assert_eq!(unmodeled_assignments[0].preceding_bindings(), 1);
    assert!(!unmodeled_assignments[0].mutates_current_shell());

    let declaration = normalize(r#"declare FIRST=one ITEMS["${target:=0}"]=value"#).unwrap();
    let [
        Statement::Command {
            assignments,
            unmodeled_assignments,
            ..
        },
    ] = declaration.statements()
    else {
        panic!("unexpected declaration syntax: {declaration:?}");
    };
    assert_eq!(assignments[0].0, "FIRST");
    assert_eq!(unmodeled_assignments[0].preceding_bindings(), 1);
    assert!(unmodeled_assignments[0].mutates_current_shell());
}

#[test]
fn arithmetic_state_mutations_retain_raw_headers_and_loop_bodies() {
    let arithmetic = normalize("((flag=1))").unwrap();
    assert!(
        matches!(
            arithmetic.statements(),
            [Statement::UnmodeledStateMutation {
                construct,
                word,
                statements,
            }] if construct == "arithmetic_command"
                && word.raw() == "((flag=1))"
                && statements.is_empty()
        ),
        "{arithmetic:?}"
    );

    let looped = normalize("for ((i=0; i<1; i++)); do echo body; done").unwrap();
    assert!(
        matches!(
            looped.statements(),
            [Statement::UnmodeledStateMutation {
                construct,
                word,
                statements,
            }] if construct == "c_style_for_statement"
                && word.raw().starts_with("for ((i=0; i<1; i++));")
                && matches!(statements.as_slice(), [Statement::Command { name, .. }] if name == "echo")
        ),
        "{looped:?}"
    );
}
