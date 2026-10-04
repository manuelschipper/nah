//! Generated parser/walker stress cases.
//!
//! Arbitrary source may produce partial evidence, but must not abort the
//! process or silently look complete. These cases are generated, not
//! hand-written fixtures: left- and right-deep trees, long chains, huge
//! flat lists, interpolation, include cycles, and large generated bodies.

use std::collections::HashMap;

use effinterp_engine::{
    Engine, Lang, ScopeKey, SourceRefusal, SourceRequest, SourceResolver, SourceResponse,
    UnavailableReason, module_summaries,
};
use effinterp_proto::{Plan, SourceDialect, Subject, validate_plan};

/// Tree-sitter CSTs are built iteratively; 20k operators is the checkstyle shape.
const DEEP_CST: usize = 25_000;
/// Rust-parser ASTs are built recursively; sized to stay inside a typical
/// 8MiB parse stack while still overflowing an unbounded walker.
const DEEP_AST: usize = 256;
const NEST: usize = 512;
const NEST_AST: usize = 128;
/// Links in a generated chain: far past what the native stack survives.
const CHAIN: usize = 50_000;
const FLAT: usize = 8_000;
const INTERP: usize = 2_000;

struct MapResolver(HashMap<String, String>);

impl SourceResolver for MapResolver {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.get(request.path).map_or_else(
            || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |source| SourceResponse::Source(source.as_bytes().to_vec()),
        )
    }

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        Some(
            self.0
                .keys()
                .filter(|candidate| {
                    candidate.as_str() != path
                        && candidate
                            .rsplit_once('/')
                            .map_or("", |(candidate_parent, _)| candidate_parent)
                            == parent
                })
                .cloned()
                .collect(),
        )
    }
}

fn engine() -> Engine {
    Engine::new()
}

fn analyze(subject: Subject) -> Plan {
    let plan = engine().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn source(language: &str, code: String) -> Subject {
    Subject::Source {
        dialect: None,
        language: language.into(),
        source: code,
        cwd: Some("/w".into()),
        context: Default::default(),
    }
}

fn has_delete(plan: &Plan, path: &str) -> bool {
    plan.effects.iter().any(|e| {
        e.operation.0 == "filesystem.delete"
            && match &e.resource {
                effinterp_proto::ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: p },
                } => p == path,
                _ => false,
            }
    })
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn truncated(plan: &Plan) -> bool {
    plan.boundaries.iter().any(|b| {
        matches!(
            b.reason.as_str(),
            "partial_analysis"
                | "limit_saturated"
                | "include_cycle"
                | "nested_limit"
                | "parse_error"
        )
    })
}

/// A planted effect before the pathology must still be found; if the walk
/// later stops, that stop must be a typed boundary, never a silent complete.
fn assert_planted_or_partial(plan: &Plan, path: &str) {
    assert!(
        has_delete(plan, path) || truncated(plan),
        "missing planted delete of {path} and no typed partial boundary; reasons={:?}",
        plan.boundaries
            .iter()
            .map(|b| b.reason.as_str())
            .collect::<Vec<_>>()
    );
}

fn summarize(lang: Lang, code: &str) {
    let scope = match lang {
        Lang::Go => ScopeKey::GoPackage { key: "pkg".into() },
        Lang::Rust => ScopeKey::RustModule {
            key: "crate".into(),
        },
        _ => ScopeKey::Module {
            key: "fixture".into(),
        },
    };
    let _ = module_summaries(
        code,
        lang,
        "fixture",
        scope,
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
    );
}

// ---------------------------------------------------------------------------
// Deep binary expressions (left- and right-associative)
// ---------------------------------------------------------------------------

fn java_left_concat(ops: usize) -> String {
    let mut s = String::from(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A { public static void main(String[] a) throws Exception { Files.delete(Path.of(\"/data\")); String s = \"x\"",
    );
    for _ in 0..ops {
        s.push_str(" + \"x\"");
    }
    s.push_str("; } }\n");
    s
}

fn java_right_concat(ops: usize) -> String {
    let mut expr = String::from("\"x\"");
    for _ in 0..ops {
        expr = format!("\"x\" + ({expr})");
    }
    format!(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A {{ public static void main(String[] a) throws Exception {{ Files.delete(Path.of(\"/data\")); String s = {expr}; }} }}\n"
    )
}

#[test]
fn java_deep_left_concat() {
    let src = java_left_concat(DEEP_CST);
    let plan = analyze(source("java", src.clone()));
    assert!(has_delete(&plan, "/data"));
    summarize(Lang::Java, &src);
}

#[test]
fn java_deep_right_concat() {
    let src = java_right_concat(NEST_AST);
    let plan = analyze(source("java", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Java, &src);
}

fn python_left_add(ops: usize) -> String {
    let mut s = String::from("import os\nos.remove('/data')\nx = 1");
    for _ in 0..ops {
        s.push_str(" + 1");
    }
    s.push('\n');
    s
}

fn python_right_add(ops: usize) -> String {
    let mut expr = String::from("1");
    for _ in 0..ops {
        expr = format!("(1 + {expr})");
    }
    format!("import os\nos.remove('/data')\nx = {expr}\n")
}

#[test]
fn python_deep_left_add() {
    let src = python_left_add(DEEP_AST);
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert!(has_delete(&plan, "/data"));
    summarize(Lang::Python, &src);
}

#[test]
fn python_deep_right_add() {
    let src = python_right_add(NEST_AST);
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Python, &src);
}

fn js_left_add(ops: usize) -> String {
    let mut s = String::from("const fs = require('fs');\nfs.unlinkSync('/data');\nlet x = 1");
    for _ in 0..ops {
        s.push_str(" + 1");
    }
    s.push_str(";\n");
    s
}

fn js_right_add(ops: usize) -> String {
    let mut expr = String::from("1");
    for _ in 0..ops {
        expr = format!("(1 + {expr})");
    }
    format!("const fs = require('fs');\nfs.unlinkSync('/data');\nlet x = {expr};\n")
}

#[test]
fn js_deep_left_add() {
    let src = js_left_add(DEEP_AST);
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.clone(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Js(SourceDialect::Js), &src);
}

#[test]
fn js_deep_right_add() {
    let src = js_right_add(NEST);
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.clone(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Js(SourceDialect::Js), &src);
}

fn go_left_add(ops: usize) -> String {
    let mut s =
        String::from("package main\nimport \"os\"\nfunc main() { os.Remove(\"/data\"); x := 1");
    for _ in 0..ops {
        s.push_str(" + 1");
    }
    s.push_str("; _ = x }\n");
    s
}

#[test]
fn go_deep_left_add() {
    let src = go_left_add(DEEP_AST);
    let plan = analyze(source("go", src.clone()));
    assert!(has_delete(&plan, "/data"));
    summarize(Lang::Go, &src);
}

fn rust_left_add(ops: usize) -> String {
    let mut s = String::from("fn main() { let _ = std::fs::remove_file(\"/data\"); let _x = 1");
    for _ in 0..ops {
        s.push_str(" + 1");
    }
    s.push_str("; }\n");
    s
}

#[test]
fn rust_deep_left_add() {
    let src = rust_left_add(DEEP_AST);
    let plan = analyze(source("rust", src.clone()));
    assert!(has_delete(&plan, "/data"));
    summarize(Lang::Rust, &src);
}

fn php_left_concat(ops: usize) -> String {
    let mut s = String::from("<?php unlink('/data'); $s = 'x'");
    for _ in 0..ops {
        s.push_str(" . 'x'");
    }
    s.push_str(";\n");
    s
}

#[test]
fn php_deep_left_concat() {
    let src = php_left_concat(DEEP_CST);
    let plan = analyze(source("php", src.clone()));
    assert!(has_delete(&plan, "/data"));
    summarize(Lang::Php, &src);
}

fn ruby_left_add(ops: usize) -> String {
    let mut s = String::from("File.delete('/data')\nx = 1");
    for _ in 0..ops {
        s.push_str(" + 1");
    }
    s.push('\n');
    s
}

#[test]
fn ruby_deep_left_add() {
    let src = ruby_left_add(DEEP_AST);
    let plan = analyze(source("ruby", src.clone()));
    // The operator chain reaches the walk limit, so the pre-parse guard refuses
    // the whole source with a boundary rather than let lib-ruby-parser build and
    // later drop a stack-deep AST; the JS sibling tolerates the same boundary.
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Ruby, &src);
}

fn shell_left_arith(ops: usize) -> String {
    let mut s = String::from("rm /data\nx=$((1");
    for _ in 0..ops {
        s.push_str("+1");
    }
    s.push_str("))\n");
    s
}

#[test]
fn shell_deep_arith() {
    let src = shell_left_arith(DEEP_AST);
    let plan = analyze(Subject::Shell {
        source: src,
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
}

// ---------------------------------------------------------------------------
// Deep calls / member chains
// ---------------------------------------------------------------------------

#[test]
fn python_deep_member_chain() {
    let mut recv = String::from("os");
    for i in 0..NEST_AST {
        recv.push_str(&format!(".a{i}"));
    }
    let src = format!("import os\nos.remove('/data')\n{recv}.x\n");
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Python, &src);
}

#[test]
fn js_deep_member_chain() {
    let mut recv = String::from("fs");
    for i in 0..NEST {
        recv.push_str(&format!(".a{i}"));
    }
    let src = format!("const fs = require('fs');\nfs.unlinkSync('/data');\n{recv}.x;\n");
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.clone(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Js(SourceDialect::Js), &src);
}

#[test]
fn js_deep_calls() {
    // f(f(f(...('/data'))))
    let mut call = String::from("'/data'");
    for _ in 0..256 {
        call = format!("id({call})");
    }
    let src = format!(
        "const fs = require('fs');\nfs.unlinkSync('/data');\nfunction id(x){{ return x; }}\n{call};\n"
    );
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src,
        dialect: Some(SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
}

#[test]
fn go_deep_calls() {
    let mut call = String::from("\"/data\"");
    for _ in 0..NEST_AST {
        call = format!("id({call})");
    }
    let src = format!(
        "package main\nimport \"os\"\nfunc id(s string) string {{ return s }}\nfunc main() {{ os.Remove(\"/data\"); _ = {call} }}\n"
    );
    let plan = analyze(source("go", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Go, &src);
}

#[test]
fn rust_deep_calls() {
    let mut call = String::from("\"/data\"");
    for _ in 0..NEST_AST {
        call = format!("id({call})");
    }
    let src = format!(
        "fn id(s: &str) -> &str {{ s }}\nfn main() {{ let _ = std::fs::remove_file(\"/data\"); let _ = {call}; }}\n"
    );
    let plan = analyze(source("rust", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Rust, &src);
}

#[test]
fn rust_recursive_closure_binding_does_not_abort() {
    let src = "fn main() {\n    std::fs::remove_file(\"/data\");\n    let f = || std::fs::remove_file(\"/shadowed\");\n    let f = || f();\n    f();\n}\n";
    let plan = analyze(source("rust", src.to_string()));
    assert_planted_or_partial(&plan, "/data");
    assert!(has_boundary(&plan, "unresolved_call"));
    summarize(Lang::Rust, src);
}

// ---------------------------------------------------------------------------
// Deep blocks / conditionals
// ---------------------------------------------------------------------------

#[test]
fn python_deep_ifs() {
    let mut src = String::from("import os\nos.remove('/data')\n");
    for _ in 0..NEST_AST {
        src.push_str("if True:\n");
    }
    src.push_str(&"    ".repeat(NEST_AST));
    src.push_str("x = 1\n");
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Python, &src);
}

#[test]
fn js_deep_ifs() {
    let mut src = String::from("const fs = require('fs');\nfs.unlinkSync('/data');\n");
    for _ in 0..NEST {
        src.push_str("if (1) { ");
    }
    src.push_str("var x = 1;");
    for _ in 0..NEST {
        src.push_str(" }");
    }
    src.push('\n');
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.clone(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Js(SourceDialect::Js), &src);
}

#[test]
fn go_deep_ifs() {
    let mut src = String::from("package main\nimport \"os\"\nfunc main() { os.Remove(\"/data\"); ");
    for _ in 0..NEST_AST {
        src.push_str("if true { ");
    }
    src.push_str("_ = 1");
    for _ in 0..NEST_AST {
        src.push_str(" }");
    }
    src.push_str(" }\n");
    let plan = analyze(source("go", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Go, &src);
}

#[test]
fn rust_deep_ifs() {
    let mut src = String::from("fn main() { let _ = std::fs::remove_file(\"/data\"); ");
    for _ in 0..32 {
        src.push_str("if true { ");
    }
    src.push_str("let _x = 1;");
    for _ in 0..32 {
        src.push_str(" }");
    }
    src.push_str(" }\n");
    let plan = analyze(source("rust", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Rust, &src);
}

#[test]
fn php_deep_ifs() {
    let mut src = String::from("<?php unlink('/data'); ");
    for _ in 0..NEST {
        src.push_str("if (1) { ");
    }
    src.push_str("$x = 1;");
    for _ in 0..NEST {
        src.push_str(" }");
    }
    src.push('\n');
    let plan = analyze(source("php", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Php, &src);
}

#[test]
fn ruby_deep_ifs() {
    let mut src = String::from("File.delete('/data')\n");
    for _ in 0..NEST_AST {
        src.push_str("if true\n");
    }
    src.push_str("x = 1\n");
    for _ in 0..NEST_AST {
        src.push_str("end\n");
    }
    let plan = analyze(source("ruby", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Ruby, &src);
}

#[test]
fn java_deep_ifs() {
    let mut src = String::from(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A { public static void main(String[] a) throws Exception { Files.delete(Path.of(\"/data\")); ",
    );
    for _ in 0..NEST {
        src.push_str("if (true) { ");
    }
    src.push_str("int x = 1;");
    for _ in 0..NEST {
        src.push_str(" }");
    }
    src.push_str(" } }\n");
    let plan = analyze(source("java", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Java, &src);
}

#[test]
fn shell_deep_groups() {
    let mut src = String::from("rm /data\n");
    for _ in 0..NEST {
        src.push_str("{ ");
    }
    src.push_str(": ");
    for _ in 0..NEST {
        src.push_str("; }");
    }
    src.push('\n');
    let plan = analyze(Subject::Shell {
        source: src,
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
}

/// A deeply nested literal handed to a recursive-descent frontend (oxc for
/// JS/TS, lib-ruby-parser for Ruby, the hand-written PowerShell reader) once
/// overflowed the native stack and aborted the whole hook, skipping every
/// guard. Each frontend must now bound the nesting before parsing: the
/// interpreter segment becomes a walk-limit boundary while the separate
/// `rm -rf /data` is still analyzed and its delete planted.
fn deep_group_command(interpreter: &str, assignment: &str) -> String {
    let mut code = String::from(assignment);
    code.push_str(&"(".repeat(NEST));
    code.push('1');
    code.push_str(&")".repeat(NEST));
    format!("{interpreter} '{code}'\nrm -rf /data\n")
}

fn assert_deep_frontend_boundary(source: String) {
    let plan = analyze(Subject::Shell {
        source,
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert!(
        has_delete(&plan, "/data"),
        "the separate rm was dropped instead of analyzed; reasons={:?}",
        plan.boundaries
            .iter()
            .map(|b| b.reason.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        plan.boundaries.iter().any(|b| {
            b.detail
                .as_deref()
                .is_some_and(|detail| detail.contains("nesting exceeds the walk limit"))
        }),
        "the deep interpreter source produced no walk-limit boundary"
    );
}

#[test]
fn js_deep_groups() {
    assert_deep_frontend_boundary(deep_group_command("node -e", "const x="));
}

#[test]
fn ruby_deep_groups() {
    assert_deep_frontend_boundary(deep_group_command("ruby -e", "x="));
}

#[test]
fn powershell_deep_groups() {
    assert_deep_frontend_boundary(deep_group_command("pwsh -c", "$x="));
}

/// A chain that nests one level per link without holding many brackets open:
/// each link closes the brackets it opens, breaks the line, or hides a closing
/// bracket in a string or regular expression. The pre-scan must still count
/// every link, or a long enough chain overflows the native stack and aborts
/// the hook instead of reaching the walk-limit boundary.
fn chain_source(head: &str, link: &str, tail: &str) -> String {
    format!("{head}{}{tail}", link.repeat(CHAIN))
}

fn assert_deep_chains_reach_the_boundary(interpreter: &str, chains: &[(&str, &str, &str)]) {
    for (head, link, tail) in chains {
        let code = chain_source(head, link, tail);
        assert_deep_frontend_boundary(format!("{interpreter} '{code}'\nrm -rf /data\n"));
    }
}

#[test]
fn js_deep_right_nested_chains() {
    assert_deep_chains_reach_the_boundary(
        "node -e",
        &[
            ("x = ", "c ? (1) : ", "0"),
            ("x = ", "c\n? 1\n: ", "0"),
            ("x = ", "(a) => ", "0"),
            ("", "if (a) {} else ", "{}"),
            ("", "if (a) b; else ", "b;"),
            ("", "if (a) b\nelse ", "b"),
            ("f", "(1)", ";"),
            ("f", "``", ";"),
            ("x = ", "class extends ", "Object {}"),
            ("x = ", "c ? () => {} : ", "0"),
            // A `}` that completes an operand: the `/` after it divides, and
            // reading it as a regular expression would skip the whole chain.
            ("x=function(){}/", "c?(1):", "0/1"),
            ("x={}/", "c?(1):", "0/1"),
            ("x=class{}/", "c?(1):", "0/1"),
            ("x=async function(){}/", "c?(1):", "0/1"),
            ("x = ", "c ? {} : ", "0"),
        ],
    );
}

/// A left-associative chain written one operand per line. The parser loops
/// over it, but the tree is as deep as the chain is long and the walkers
/// recurse on it, so past the limit it must reach the boundary too.
#[test]
fn js_deep_line_broken_left_chains() {
    assert_deep_chains_reach_the_boundary(
        "node -e",
        &[
            ("let x = 1", "\n+1", ";"),
            ("x = 1", "\n&& a", ";"),
            ("x = 1", "\ninstanceof a", ";"),
            ("f", "\n(1)", ";"),
            ("f", "\n.a()", ";"),
            ("f", "\n`a`", ";"),
        ],
    );
}

#[test]
fn js_deep_groups_closed_only_in_literals() {
    assert_deep_chains_reach_the_boundary(
        "node -e",
        &[
            ("x = ", "(`)` + ", "0"),
            ("x = ", "(/[)]/ + ", "0"),
            ("", "{ if (a) /}/; ", "0"),
            ("", "{ {} /}/; ", "0"),
            ("function f() {", "{ return /}/; ", "0"),
            ("", "{ x++ / (y / 1); ", "0"),
            ("", "{ a: {} /}/; ", "0"),
            ("", "switch (x) { case 1: {} /}/; ", "0"),
            ("async function f() {", "{ for await (a of b) /}/; ", "0"),
            ("", "{ x = () => {}\n/}/; ", "0"),
        ],
    );
}

#[test]
fn ts_deep_type_chains() {
    for (head, link, tail) in [
        ("let x: ", "A<B, ", format!("C{};", ">".repeat(CHAIN))),
        ("type X = ", "keyof ", "T;".to_string()),
    ] {
        let plan = analyze(Subject::Source {
            language: "js".into(),
            source: chain_source(head, link, &tail),
            dialect: Some(SourceDialect::Ts),
            cwd: Some("/w".into()),
            context: Default::default(),
        });
        assert!(truncated(&plan), "{link:?} chain produced no boundary");
    }
}

#[test]
fn ruby_deep_right_nested_chains() {
    assert_deep_chains_reach_the_boundary(
        "ruby -e",
        &[
            ("x = ", "c ? (1) : ", "0"),
            ("if a\n", "elsif (a)\n", "end"),
        ],
    );
}

/// The pre-scan over-counts by design, so it must not mistake ordinary
/// siblings for depth: a false boundary would drop the planted delete along
/// with the rest of the source, and padding a file would hide its effects.
#[test]
fn long_flat_sources_stay_inside_the_walk_limit() {
    let statements =
        "if (a) { f(x).g(y)[0]; } else if (b) { h(`${x}`, /[)]/); } else { k = c ? (1) : 2; }\n\
                      function m(p) { return p }\nclass K { a() {} b() {} }\n"
            .repeat(NEST);
    let comparisons = format!("const a = [{}];\n", "x<1,".repeat(NEST));
    let classes: String = (0..NEST).map(|n| format!("class C{n} {{}}\n")).collect();
    let line_chain = format!("let s = 1{};\n", "\n+1".repeat(NEST - 32));
    for (language, delete, padding) in [
        ("js", "require('fs').unlinkSync('/data');\n", statements),
        ("js", "require('fs').unlinkSync('/data');\n", comparisons),
        ("js", "require('fs').unlinkSync('/data');\n", classes),
        ("js", "require('fs').unlinkSync('/data');\n", line_chain),
        (
            "ruby",
            "File.delete('/data')\n",
            format!("a = [{}]\n", "x < 1, ".repeat(NEST)),
        ),
    ] {
        let plan = analyze(Subject::Source {
            dialect: (language == "js").then_some(SourceDialect::Js),
            language: language.into(),
            source: format!("{delete}{padding}"),
            cwd: Some("/w".into()),
            context: Default::default(),
        });
        let head = &padding[..padding.len().min(24)];
        assert!(has_delete(&plan, "/data"), "{head:?} dropped the delete");
        assert!(
            !plan.boundaries.iter().any(|b| {
                b.detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("nesting exceeds the walk limit"))
            }),
            "{head:?} reached the walk limit"
        );
    }
}

// ---------------------------------------------------------------------------
// Huge flat argument / array lists
// ---------------------------------------------------------------------------

#[test]
fn python_huge_arg_list() {
    let mut src = String::from("import os\nos.remove('/data')\nprint(");
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push_str(&i.to_string());
    }
    src.push_str(")\n");
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Python, &src);
}

#[test]
fn js_huge_array() {
    let mut src = String::from("const fs = require('fs');\nfs.unlinkSync('/data');\nconst a = [");
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push_str(&i.to_string());
    }
    src.push_str("];\n");
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.clone(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Js(SourceDialect::Js), &src);
}

#[test]
fn go_huge_slice() {
    let mut src =
        String::from("package main\nimport \"os\"\nfunc main() { os.Remove(\"/data\"); _ = []int{");
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push_str(&i.to_string());
    }
    src.push_str("} }\n");
    let plan = analyze(source("go", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Go, &src);
}

#[test]
fn rust_huge_array() {
    let mut src = String::from("fn main() { let _ = std::fs::remove_file(\"/data\"); let _x = [");
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push('0');
    }
    src.push_str("]; }\n");
    let plan = analyze(source("rust", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Rust, &src);
}

#[test]
fn php_huge_array() {
    let mut src = String::from("<?php unlink('/data'); $a = [");
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push_str(&i.to_string());
    }
    src.push_str("];\n");
    let plan = analyze(source("php", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Php, &src);
}

#[test]
fn ruby_huge_array() {
    let mut src = String::from("File.delete('/data')\na = [");
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push_str(&i.to_string());
    }
    src.push_str("]\n");
    let plan = analyze(source("ruby", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Ruby, &src);
}

#[test]
fn java_huge_array() {
    let mut src = String::from(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A { public static void main(String[] a) throws Exception { Files.delete(Path.of(\"/data\")); int[] xs = {",
    );
    for i in 0..FLAT {
        if i > 0 {
            src.push(',');
        }
        src.push('1');
    }
    src.push_str("}; } }\n");
    let plan = analyze(source("java", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Java, &src);
}

// ---------------------------------------------------------------------------
// Pathological interpolation
// ---------------------------------------------------------------------------

#[test]
fn python_interpolation() {
    let mut src = String::from("import os\nos.remove('/data')\ns = f'");
    for _ in 0..INTERP {
        src.push_str("{1}");
    }
    src.push_str("'\n");
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Python, &src);
}

#[test]
fn js_interpolation() {
    let mut src = String::from("const fs = require('fs');\nfs.unlinkSync('/data');\nconst s = `");
    for _ in 0..INTERP {
        src.push_str("${1}");
    }
    src.push_str("`;\n");
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.clone(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Js(SourceDialect::Js), &src);
}

#[test]
fn php_interpolation() {
    let mut src = String::from("<?php unlink('/data'); $s = \"");
    for i in 0..INTERP {
        src.push_str(&format!("$a{i}"));
    }
    src.push_str("\";\n");
    let plan = analyze(source("php", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Php, &src);
}

#[test]
fn ruby_interpolation() {
    let mut src = String::from("File.delete('/data')\ns = \"");
    for _ in 0..INTERP {
        src.push_str("#{1}");
    }
    src.push_str("\"\n");
    let plan = analyze(source("ruby", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Ruby, &src);
}

#[test]
fn shell_interpolation() {
    let mut src = String::from("rm /data\ns=\"");
    for i in 0..INTERP {
        src.push_str(&format!("${{a{i}}}"));
    }
    src.push_str("\"\n");
    let plan = analyze(Subject::Shell {
        source: src,
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
}

// ---------------------------------------------------------------------------
// Recursive import / include cycles
// ---------------------------------------------------------------------------

#[test]
fn php_include_cycle_does_not_abort() {
    let e = Engine::new().with_resolver(Box::new(MapResolver(
        [
            (
                "/w/a.php".into(),
                "<?php require __DIR__ . '/b.php';".into(),
            ),
            (
                "/w/b.php".into(),
                "<?php require __DIR__ . '/a.php';".into(),
            ),
        ]
        .into_iter()
        .collect(),
    )));
    let plan = e
        .analyze(&source(
            "php",
            "<?php unlink('/data'); require __DIR__ . '/a.php';".into(),
        ))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has_delete(&plan, "/data"));
    assert!(
        has_boundary(&plan, "include_cycle") || truncated(&plan),
        "cycle must be a typed boundary: {:?}",
        plan.boundaries
            .iter()
            .map(|b| b.reason.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn python_import_cycle_source_does_not_abort() {
    // A single file cannot follow a cycle; the source must still parse and
    // walk. Mutual imports are a compose concern, not a walker crash.
    let src = "import os\nos.remove('/data')\nimport a\nimport b\n";
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.into(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert!(has_delete(&plan, "/data"));
}

#[test]
fn js_import_cycle_source_does_not_abort() {
    let src =
        "const fs = require('fs');\nfs.unlinkSync('/data');\nimport './a.js';\nimport './b.js';\n";
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src.into(),
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
}

#[test]
fn go_import_cycle_source_does_not_abort() {
    let src = "package main\nimport \"os\"\nimport _ \"a\"\nimport _ \"b\"\nfunc main() { os.Remove(\"/data\") }\n";
    let plan = analyze(source("go", src.into()));
    assert_planted_or_partial(&plan, "/data");
}

#[test]
fn rust_use_cycle_source_does_not_abort() {
    let src = "use a::b;\nuse b::a;\nfn main() { let _ = std::fs::remove_file(\"/data\"); }\n";
    let plan = analyze(source("rust", src.into()));
    assert_planted_or_partial(&plan, "/data");
}

#[test]
fn ruby_require_cycle_source_does_not_abort() {
    let src = "File.delete('/data')\nrequire 'a'\nrequire 'b'\n";
    let plan = analyze(source("ruby", src.into()));
    assert!(has_delete(&plan, "/data"));
}

#[test]
fn java_import_cycle_source_does_not_abort() {
    let src = "import java.nio.file.Files;\nimport java.nio.file.Path;\nimport a.A;\nimport b.B;\npublic class C { public static void main(String[] a) throws Exception { Files.delete(Path.of(\"/data\")); } }\n";
    let plan = analyze(source("java", src.into()));
    assert!(has_delete(&plan, "/data"));
}

// ---------------------------------------------------------------------------
// Large macro / generated bodies
// ---------------------------------------------------------------------------

#[test]
fn rust_large_generated_body() {
    let mut src = String::from("fn main() { let _ = std::fs::remove_file(\"/data\"); ");
    for i in 0..FLAT {
        src.push_str(&format!("let _v{i} = {i}; "));
    }
    src.push_str("}\n");
    let plan = analyze(source("rust", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Rust, &src);
}

#[test]
fn rust_large_macro_body() {
    let mut src = String::from("macro_rules! gen { () => { ");
    for i in 0..FLAT {
        src.push_str(&format!("let _v{i} = {i}; "));
    }
    src.push_str("}; }\nfn main() { let _ = std::fs::remove_file(\"/data\"); gen!(); }\n");
    let plan = analyze(source("rust", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Rust, &src);
}

#[test]
fn java_large_generated_body() {
    let mut src = String::from(
        "import java.nio.file.Files;\nimport java.nio.file.Path;\npublic class A { public static void main(String[] a) throws Exception { Files.delete(Path.of(\"/data\")); ",
    );
    for i in 0..FLAT {
        src.push_str(&format!("int v{i} = {i}; "));
    }
    src.push_str("} }\n");
    let plan = analyze(source("java", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Java, &src);
}

#[test]
fn python_large_generated_body() {
    let mut src = String::from("import os\nos.remove('/data')\n");
    for i in 0..FLAT {
        src.push_str(&format!("v{i} = {i}\n"));
    }
    let plan = analyze(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.clone(),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Python, &src);
}

#[test]
fn php_large_generated_body() {
    let mut src = String::from("<?php unlink('/data'); ");
    for i in 0..FLAT {
        src.push_str(&format!("$v{i} = {i}; "));
    }
    src.push('\n');
    let plan = analyze(source("php", src.clone()));
    assert_planted_or_partial(&plan, "/data");
    summarize(Lang::Php, &src);
}

#[test]
fn js_wide_spreads_saturate_flow_slots() {
    let mut src = String::from("const table = {");
    for i in 0..2_000 {
        src.push_str(&format!("p{i}: 'safe',"));
    }
    src.push_str("};\n");
    for i in 0..5 {
        let source = if i == 0 {
            "table".to_string()
        } else {
            format!("copy{}", i - 1)
        };
        src.push_str(&format!("const copy{i} = {{ ...{source} }};\n"));
    }
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src,
        dialect: Some(SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.limit.as_deref() == Some("max_js_causal_slots")
    }));
}

#[test]
fn unsupported_process_receiver_is_a_typed_partial_boundary() {
    let plan = analyze(Subject::Source { language: "js".into(),
        source: "const process = globalThis.process; const a = process.env.A; const b = process.env.B; const c = process.env.C".into(),
        dialect: Some(SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| {
                boundary.reason.as_str() == "partial_analysis"
                    && boundary
                        .domains
                        .iter()
                        .any(|domain| domain.0 == "environment")
            })
            .count(),
        1
    );
}

/// A walk that hits a bound must not claim a complete result: coverage stays
/// partial and a typed boundary is present.
#[test]
fn depth_bound_is_visible() {
    let mut src = String::from("const fs = require('fs');\nfs.unlinkSync('/data');\n");
    for _ in 0..NEST {
        src.push_str("if (1) { ");
    }
    src.push_str("var x = 1;");
    for _ in 0..NEST {
        src.push_str(" }");
    }
    let plan = analyze(Subject::Source {
        language: "js".into(),
        source: src,
        dialect: Some(effinterp_proto::SourceDialect::Js),
        cwd: Some("/w".into()),
        context: Default::default(),
    });
    assert!(has_delete(&plan, "/data") || truncated(&plan));
    if !has_delete(&plan, "/data") {
        assert!(
            has_boundary(&plan, "partial_analysis") || has_boundary(&plan, "limit_saturated"),
            "truncated walk must emit a typed boundary"
        );
    }
}

#[test]
fn shell_brace_expansion_growth() {
    for word in [
        format!("{}x{}", "{a,b,c,d,".repeat(64), "}".repeat(64)),
        "{a,b}".repeat(20),
    ] {
        let plan = analyze(Subject::Shell {
            source: format!("rm /data; rm /{word}"),
            cwd: Some("/w".into()),
            context: Default::default(),
        });
        assert_planted_or_partial(&plan, "/data");
        assert!(has_boundary(&plan, "limit_saturated"));
    }
}
