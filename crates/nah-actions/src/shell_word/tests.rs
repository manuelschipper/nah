use super::*;

#[test]
fn quoting_and_environment_references_are_conservative() {
    assert_eq!(
        static_word("'literal $VALUE'", true).as_deref(),
        Some("literal $VALUE")
    );
    assert_eq!(static_word("out\\ file", true).as_deref(), Some("out file"));
    assert_eq!(static_word("\"\"", true).as_deref(), Some(""));
    assert_eq!(static_word("\"out\\x\"", true).as_deref(), Some("out\\x"));
    assert_eq!(
        static_word("$'rm\\x20-rf\\x20/'", true).as_deref(),
        Some("rm -rf /")
    );
    assert_eq!(
        static_word("pre$'line\\n'post", true).as_deref(),
        Some("preline\npost")
    );
    assert!(static_word("$'bad\\q'", true).is_none());
    assert!(static_word("$'nul\\000byte'", true).is_none());
    assert!(static_word("\"$VALUE\"", true).is_none());
    assert_eq!(exact_env_name("\"${TOOL}\""), Some("TOOL"));
    assert_eq!(
        static_filesystem_word("\"$HOME/.ssh/id_rsa\"", true).as_deref(),
        Some("~/.ssh/id_rsa")
    );
    assert_eq!(
        static_filesystem_word("'${HOME}/.ssh/id_rsa'", true).as_deref(),
        Some("${HOME}/.ssh/id_rsa")
    );
    // The quoting may close right after the variable; the fragments still
    // concatenate into one path.
    for raw in [
        "\"$HOME\"/.ssh/id_rsa",
        "\"${HOME}\"/.ssh/id_rsa",
        "$HOME/.ssh/id_rsa",
        "${HOME}/.ssh/id_rsa",
    ] {
        assert_eq!(
            static_filesystem_word(raw, true).as_deref(),
            Some("~/.ssh/id_rsa"),
            "{raw}"
        );
    }
    assert_eq!(
        static_filesystem_word("\"$HOME\"", true).as_deref(),
        Some("~")
    );
    for raw in [
        "\"$PWD\"/src/lib.rs",
        "\"${PWD}/src/lib.rs\"",
        "$PWD/src/lib.rs",
        "${PWD}/src/lib.rs",
    ] {
        assert_eq!(
            static_filesystem_word(raw, true).as_deref(),
            Some("~+/src/lib.rs"),
            "{raw}"
        );
    }
    assert!(static_filesystem_word("\"$HOMEDIR\"/x", true).is_none());
    assert_eq!(
        static_filesystem_word("\"~/.ssh/id_rsa\"", true).as_deref(),
        Some("./~/.ssh/id_rsa")
    );
    assert_eq!(
        referenced_env_names("'$NO' \"$YES\" ${ALSO} \\$ESCAPED"),
        ["ALSO", "YES"]
    );
    assert_eq!(referenced_env_names("${rows[0]} ${rows[$index]}"), ["rows"]);
    assert_eq!(
        referenced_env_names("${OUTER:-${INNER:=/}} ${ROWS[0]:=safe}"),
        ["INNER", "OUTER", "ROWS"]
    );
    assert!(referenced_env_names("'${TARGET:=/}'").is_empty());
    assert_eq!(
        here_document_referenced_env_names("'${TARGET:=/}'"),
        ["TARGET"]
    );
    assert_eq!(
        referenced_positional_names("$1 ${22} '$3' \\$4 \"$@\" ${@} $10"),
        ["1", "22", "@"]
    );
    for raw in ["/et?", "/et[c]", "/{,}", "~/.na?", "a\"b\"?"] {
        assert!(contains_unquoted_pattern(raw), "{raw}");
    }
    for raw in [
        "'/et?'",
        "\"/et?\"",
        "/et\\?",
        "'.git/{objects,refs}'",
        "/etc",
    ] {
        assert!(!contains_unquoted_pattern(raw), "{raw}");
    }
    assert!(has_unmodeled_expansion("\"$TOKEN\""));
    assert!(has_unmodeled_expansion("$((1 + 2))"));
    assert!(has_unmodeled_expansion("/etc/*"));
    assert!(has_unmodeled_expansion("~"));
    assert!(!has_unmodeled_expansion("'$TOKEN'"));
    assert!(!has_unmodeled_expansion("\"*\""));
    assert!(!has_unmodeled_expansion("$(date)"));
}

#[test]
fn local_values_preserve_shell_word_shape() {
    let variables = vec![
        ("P".to_owned(), VariableValue::Static("/".to_owned())),
        (
            "GLOB".to_owned(),
            VariableValue::Static("/etc/*".to_owned()),
        ),
        (
            "SPLIT".to_owned(),
            VariableValue::Static("one two".to_owned()),
        ),
        ("EMPTY".to_owned(), VariableValue::Unset),
        ("UNKNOWN".to_owned(), VariableValue::Unknown),
    ];

    assert_eq!(
        resolve_word(
            "\"${P}etc\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Static {
            value: "/etc".to_owned(),
            changed: true,
        }
    );
    assert_eq!(
        resolve_word(
            "$GLOB",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Pattern {
            value: "/etc/*".to_owned(),
            changed: true,
        }
    );
    assert!(matches!(
        resolve_word(
            "$SPLIT",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Unresolved { .. }
    ));
    assert_eq!(
        resolve_word(
            "$EMPTY",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Absent
    );
    assert_eq!(
        resolve_word(
            "\"$EMPTY\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Static {
            value: String::new(),
            changed: true,
        }
    );
    assert!(matches!(
        resolve_word(
            "\"$UNKNOWN\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Unresolved {
            literal_prefix,
            may_be_absolute: true,
            ..
        } if literal_prefix.is_empty()
    ));
}

#[test]
fn assignments_do_not_apply_word_splitting_or_globbing() {
    let variables = vec![(
        "VALUE".to_owned(),
        VariableValue::Static("one * two".to_owned()),
    )];
    assert_eq!(
        resolve_word(
            "$VALUE",
            &[],
            &variables,
            ExpansionContext::Assignment,
            |_| None,
        ),
        ResolvedWord::Static {
            value: "one * two".to_owned(),
            changed: true,
        }
    );
}

#[test]
fn unresolved_words_preserve_their_resolution_cause() {
    let variables = vec![
        (
            "VALUE".to_owned(),
            VariableValue::Static("rm -rf /".to_owned()),
        ),
        ("UNSET".to_owned(), VariableValue::Unset),
        ("UNKNOWN".to_owned(), VariableValue::Unknown),
    ];
    for raw in [
        r#""${VALUE%/}""#,
        r#""${VALUE/rm/echo}""#,
        r#""${VALUE:1}""#,
        r#""${!NAME}""#,
        "$VALUE",
        r#""${UNSET:-${VALUE}}""#,
        r#""${UNKNOWN:+rm -rf /}""#,
        r#""${UNKNOWN:-rm -rf /}""#,
        r#""$((VALUE+1))""#,
    ] {
        assert!(
            matches!(
                resolve_word(raw, &[], &variables, ExpansionContext::ShellWord, |_| None),
                ResolvedWord::Unresolved {
                    cause: UnresolvedCause::ShellTransformation,
                    ..
                }
            ),
            "{raw}",
        );
    }

    assert!(matches!(
        resolve_word(
            r#""$UNKNOWN""#,
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Unresolved {
            cause: UnresolvedCause::UnknownValue,
            ..
        }
    ));
    let substitutions = vec![Substitution::Command {
        statements: Vec::new(),
    }];
    assert!(matches!(
        resolve_word(
            r#""$(unknown)""#,
            &substitutions,
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Unresolved {
            cause: UnresolvedCause::UnknownValue,
            ..
        }
    ));
}

#[test]
fn exact_parameter_defaults_and_arithmetic_are_resolved() {
    let variables = vec![
        ("UNSET".to_owned(), VariableValue::Unset),
        ("EMPTY".to_owned(), VariableValue::Static(String::new())),
        (
            "VALUE".to_owned(),
            VariableValue::Static("present".to_owned()),
        ),
        ("ROWS".to_owned(), VariableValue::Static("first".to_owned())),
    ];
    for raw in [
        "\"${UNSET:-rm -rf /}\"",
        "\"${EMPTY:-rm -rf /}\"",
        "\"${UNSET-rm -rf /}\"",
        "\"${UNSET:=rm -rf /}\"",
        "\"${EMPTY:=rm -rf /}\"",
        "\"${UNSET=rm -rf /}\"",
        "\"${VALUE:+rm -rf /}\"",
        "\"${VALUE+rm -rf /}\"",
        "\"${EMPTY+rm -rf /}\"",
    ] {
        assert_eq!(
            resolve_word(raw, &[], &variables, ExpansionContext::ShellWord, |_| None),
            ResolvedWord::Static {
                value: "rm -rf /".to_owned(),
                changed: true,
            },
            "{raw}",
        );
    }
    assert_eq!(
        resolve_word(
            "\"${VALUE:-rm -rf /}\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Static {
            value: "present".to_owned(),
            changed: true,
        },
    );
    for raw in [
        "\"${UNSET:+rm -rf /}\"",
        "\"${EMPTY:+rm -rf /}\"",
        "\"${UNSET+rm -rf /}\"",
        "\"${EMPTY=rm -rf /}\"",
    ] {
        assert_eq!(
            resolve_word(raw, &[], &variables, ExpansionContext::ShellWord, |_| None),
            ResolvedWord::Static {
                value: String::new(),
                changed: true,
            },
            "{raw}",
        );
    }
    assert_eq!(
        resolve_word(
            "\"${VALUE:=rm -rf /}\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Static {
            value: "present".to_owned(),
            changed: true,
        },
    );
    for raw in [
        "\"${UNSET:=safe}\"",
        "\"${EMPTY:=safe}\"",
        "\"${UNSET=safe}\"",
    ] {
        assert!(parameter_assignment_required(raw, &variables), "{raw}");
    }
    for raw in [
        "\"${VALUE:=safe}\"",
        "\"${EMPTY=safe}\"",
        "\"${VALUE=safe}\"",
        "\"${VALUE:+safe}\"",
        "'${UNSET:=safe}'",
        "\\${UNSET:=safe}",
    ] {
        assert!(!parameter_assignment_required(raw, &variables), "{raw}");
    }
    assert_eq!(
        resolve_word(
            "\"${ROWS[0]}\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Static {
            value: "first".to_owned(),
            changed: true,
        },
    );
    assert!(matches!(
        resolve_word(
            "\"${ROWS[1]}\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Unresolved { .. }
    ));
    assert_eq!(
        resolve_word(
            "\": $((1+1)); rm -rf /\"",
            &[],
            &variables,
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Static {
            value: ": 2; rm -rf /".to_owned(),
            changed: true,
        },
    );
}

#[test]
fn pure_known_substitution_output_is_resolved() {
    let substitutions = vec![Substitution::Command {
        statements: Vec::new(),
    }];
    assert_eq!(
        resolve_word(
            "$(printf rm)",
            &substitutions,
            &[],
            ExpansionContext::ShellWord,
            |_| Some("rm".to_owned()),
        ),
        ResolvedWord::Static {
            value: "rm".to_owned(),
            changed: true,
        }
    );
    assert_eq!(
        resolve_word(
            "$(printf r)m",
            &substitutions,
            &[],
            ExpansionContext::ShellWord,
            |_| Some("r".to_owned()),
        ),
        ResolvedWord::Static {
            value: "rm".to_owned(),
            changed: true,
        }
    );
    assert_eq!(
        resolve_word(
            "\"$(unknown)\"",
            &substitutions,
            &[],
            ExpansionContext::ShellWord,
            |_| None,
        ),
        ResolvedWord::Unresolved {
            literal_prefix: String::new(),
            may_be_absolute: true,
            cause: UnresolvedCause::UnknownValue,
        }
    );
}
