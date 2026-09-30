use gosyn::ast::{Comment, Declaration, Expression};
use gosyn::parse_source;

use std::rc::Rc;

fn comment_texts(comments: &[Rc<Comment>]) -> Vec<&str> {
    comments
        .iter()
        .map(|comment| comment.text.as_str())
        .collect()
}

#[test]
fn assigns_lead_comments_at_line_boundaries() {
    struct Case {
        name: &'static str,
        source: &'static str,
        docs: &'static [&'static str],
        all: &'static [&'static str],
    }

    let cases = [
        Case {
            name: "block comment on the package line",
            source: "/* 文档🙂 */package p\n",
            docs: &["/* 文档🙂 */"],
            all: &["/* 文档🙂 */"],
        },
        Case {
            name: "line comment before the package with CRLF",
            source: "// 文档🙂\r\npackage p\n",
            docs: &["// 文档🙂\r"],
            all: &["// 文档🙂\r"],
        },
        Case {
            name: "line comment separated by a blank line",
            source: "\n// detached\n\npackage p\n",
            docs: &[],
            all: &["// detached"],
        },
        Case {
            name: "multiline block comment before the package with CRLF",
            source: "/* 第一行🙂\r\n第二行\r\n第三行 */\r\npackage p\n",
            docs: &["/* 第一行🙂\r\n第二行\r\n第三行 */"],
            all: &["/* 第一行🙂\r\n第二行\r\n第三行 */"],
        },
        Case {
            name: "multiline block comment separated by a blank line",
            source: "/* 第一行🙂\r\n第二行\r\n第三行 */\r\n\r\npackage p\n",
            docs: &[],
            all: &["/* 第一行🙂\r\n第二行\r\n第三行 */"],
        },
        Case {
            name: "adjacent comments in one group",
            source: "/* first */ /* second */\npackage p\n",
            docs: &["/* first */", "/* second */"],
            all: &["/* first */", "/* second */"],
        },
        Case {
            name: "blank line starts a new comment group",
            source: "\n/* discarded */\n\n/* kept */\npackage p\n",
            docs: &["/* kept */"],
            all: &["/* discarded */", "/* kept */"],
        },
        Case {
            name: "blank line after the last comment clears the group",
            source: "/* first */\n/* second */\n\npackage p\n",
            docs: &[],
            all: &["/* first */", "/* second */"],
        },
    ];

    for case in cases {
        let file = parse_source(case.source).unwrap_or_else(|error| {
            panic!("failed to parse {}: {error}", case.name);
        });
        assert_eq!(comment_texts(&file.docs), case.docs, "{}", case.name);
        assert_eq!(comment_texts(&file.comments), case.all, "{}", case.name);
    }
}

#[test]
fn drained_lead_comments_do_not_leak_to_following_nodes() {
    let source = r#"/* file */
package p

func bare() {}

/* first function */
func first() {}

type S struct {
    /* first field */
    A int
    B int
}

var (
    /* first spec */
    a = 1
    b = 2
)

/* trailing */
"#;

    let file = parse_source(source).unwrap();
    assert_eq!(comment_texts(&file.docs), ["/* file */"]);

    let [Declaration::Function(bare), Declaration::Function(first), Declaration::Type(types), Declaration::Variable(vars)] =
        file.decl.as_slice()
    else {
        panic!("unexpected declaration layout: {:#?}", file.decl);
    };

    assert!(bare.docs.is_empty());
    assert_eq!(comment_texts(&first.docs), ["/* first function */"]);

    let Expression::TypeStruct(struct_type) = &types.specs[0].typ else {
        panic!("expected a struct type, got {:#?}", types.specs[0].typ);
    };
    assert_eq!(
        comment_texts(&struct_type.fields[0].comments),
        ["/* first field */"]
    );
    assert!(struct_type.fields[1].comments.is_empty());

    assert_eq!(comment_texts(&vars.specs[0].docs), ["/* first spec */"]);
    assert!(vars.specs[1].docs.is_empty());
    assert_eq!(file.comments.last().unwrap().text, "/* trailing */");
}

#[test]
fn preserves_inline_and_rolled_back_field_comments() {
    let source = r#"package p
type S struct {
    A int // inline line comment
    B int
    // leading comment after rollback
    C int
    D int; E int
    F int /* inline block comment */
}
"#;

    let file = parse_source(source).unwrap();
    let Declaration::Type(types) = &file.decl[0] else {
        panic!("expected a type declaration, got {:#?}", file.decl[0]);
    };
    let Expression::TypeStruct(struct_type) = &types.specs[0].typ else {
        panic!("expected a struct type, got {:#?}", types.specs[0].typ);
    };

    let fields = &struct_type.fields;
    assert_eq!(fields.len(), 6);
    assert_eq!(
        comment_texts(&fields[0].comments),
        ["// inline line comment"]
    );
    assert!(fields[1].comments.is_empty());
    assert_eq!(
        comment_texts(&fields[2].comments),
        ["// leading comment after rollback"]
    );
    assert!(fields[3].comments.is_empty());
    assert!(fields[4].comments.is_empty());
    assert_eq!(
        comment_texts(&fields[5].comments),
        ["/* inline block comment */"]
    );
}

#[test]
fn comments_crossing_parser_backtracking_do_not_leak() {
    let cases = [
        (
            "package p\ntype Array [N /* length */]int\n\nfunc after() {}\n",
            "/* length */",
        ),
        (
            "package p\ntype Generic[T /* parameter */ any] []T\n\nfunc after() {}\n",
            "/* parameter */",
        ),
        (
            "package p\ntype Constraint interface { T /* union */ | U }\n\nfunc after() {}\n",
            "/* union */",
        ),
    ];

    for (source, expected_comment) in cases {
        let file = parse_source(source).unwrap();
        let [Declaration::Type(types), Declaration::Function(after)] = file.decl.as_slice() else {
            panic!(
                "unexpected declarations after backtracking: {:#?}",
                file.decl
            );
        };

        assert!(types.docs.is_empty());
        assert!(types.specs[0].docs.is_empty());
        assert!(after.docs.is_empty());

        let comments = comment_texts(&file.comments);
        assert!(!comments.is_empty());
        assert!(comments.iter().all(|comment| *comment == expected_comment));
    }
}

#[test]
fn parses_long_unicode_comment_before_many_same_line_tokens() {
    const STATEMENT_COUNT: usize = 200;

    let comment = format!("/*{}*/", "文🙂".repeat(20_000));
    let source = format!(
        "package p\nfunc f() {{\n{comment}\n{}\n}}\n",
        "x = x + 1;".repeat(STATEMENT_COUNT)
    );

    let file = parse_source(source).unwrap();
    assert_eq!(comment_texts(&file.comments), [comment.as_str()]);

    let Declaration::Function(function) = &file.decl[0] else {
        panic!("expected a function declaration, got {:#?}", file.decl[0]);
    };
    assert_eq!(function.body.as_ref().unwrap().list.len(), STATEMENT_COUNT);
}
