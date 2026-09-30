#![allow(clippy::disallowed_methods)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use effinterp_engine::{
    Engine, Lang, ModuleSummary, ScopeKey, SemanticValue, SemanticValueKind, ValueLimits,
    WidenReason, module_summaries,
};
use effinterp_proto::{ResourceExpr, ResourceIdentity, SourceDialect, Subject, canonical_json};
use effinterp_repo::{
    IndexLimits, RepoChange, apply_changes, build_index, normalize_surface, save_index,
};

const FRONTENDS: &[&str] = &[
    "python",
    "javascript",
    "typescript",
    "go",
    "rust",
    "java",
    "ruby",
    "php",
    "shell",
];
const CATEGORIES: &[&str] = &[
    "positive",
    "negative",
    "adversarial",
    "ambiguity",
    "perturbation",
    "branch",
    "alias",
    "callback",
    "object",
    "collection",
    "return_exception",
    "resource",
    "widening",
];

fn language(frontend: &str) -> Option<(Lang, &'static str, ScopeKey)> {
    Some(match frontend {
        "python" => (
            Lang::Python,
            "app.py",
            ScopeKey::Module { key: "app".into() },
        ),
        "javascript" => (
            Lang::Js(SourceDialect::Js),
            "app.js",
            ScopeKey::Module {
                key: "app.js".into(),
            },
        ),
        "typescript" => (
            Lang::Js(SourceDialect::Ts),
            "app.ts",
            ScopeKey::Module {
                key: "app.ts".into(),
            },
        ),
        "go" => (
            Lang::Go,
            "main.go",
            ScopeKey::GoPackage { key: "app".into() },
        ),
        "rust" => (
            Lang::Rust,
            "main.rs",
            ScopeKey::RustModule { key: "app".into() },
        ),
        "java" => (
            Lang::Java,
            "App.java",
            ScopeKey::Module {
                key: "App.java".into(),
            },
        ),
        "ruby" => (
            Lang::Ruby,
            "app.rb",
            ScopeKey::Module {
                key: "app.rb".into(),
            },
        ),
        "php" => (
            Lang::Php,
            "app.php",
            ScopeKey::Module {
                key: "app.php".into(),
            },
        ),
        "shell" => return None,
        _ => unreachable!(),
    })
}

fn fixture_source(frontend: &str, category: &str, variant: usize) -> String {
    let value = match category {
        "resource" => format!("https://example.test/v{variant}"),
        "adversarial" => format!("../../tmp/{variant}/../value"),
        _ => format!("data/{category}-{variant}.txt"),
    };
    let second = format!("data/{category}-{variant}-other.txt");
    match frontend {
        "python" => match category {
            "negative" => format!("def run():\n    return {variant}\n"),
            "ambiguity" | "branch" => format!(
                "def sink(p): pass\ndef run(flag):\n    if flag:\n        sink('{value}')\n    else:\n        sink('{second}')\n"
            ),
            "alias" => format!(
                "def sink(p): pass\ndef run():\n    value = '{value}'\n    sink(value)\n"
            ),
            "callback" => {
                "def callback(): pass\ndef sink(p): pass\ndef run(): sink(callback)\n".into()
            }
            "object" => "class Item: pass\ndef sink(p): pass\ndef run(): sink(Item())\n".into(),
            "collection" => format!(
                "def sink(p): pass\ndef run(): sink(['{value}', '{second}'])\n"
            ),
            "return_exception" => format!(
                "def value(): return '{value}'\ndef fail(): raise ValueError('{variant}')\ndef sink(p): pass\ndef run(): sink(value())\n"
            ),
            "widening" => format!(
                "import os\ndef sink(p): pass\ndef run(): sink(os.path.join('a','b','c','d','{variant}'))\n"
            ),
            _ => format!("def sink(p): pass\ndef run(): sink('{value}')\n"),
        },
        "javascript" | "typescript" => match category {
            "negative" => format!("function run() {{ return {variant} }}"),
            "ambiguity" | "branch" => format!(
                "function sink(p) {{}} function run(flag) {{ if (flag) sink('{value}'); else sink('{second}'); }}"
            ),
            "alias" => format!(
                "function sink(p) {{}} function run() {{ const value = '{value}'; sink(value); }}"
            ),
            "callback" => {
                "function callback() {} function sink(p) {} function run() { sink(callback); }".into()
            }
            "object" => {
                "class Item {} function sink(p) {} function run() { sink(new Item()); }".into()
            }
            "collection" => format!(
                "function sink(p) {{}} function run() {{ sink(['{value}', '{second}']); }}"
            ),
            "return_exception" => format!(
                "function value() {{ return '{value}' }} function fail() {{ throw new Error('{variant}') }} function sink(p) {{}} function run() {{ sink(value()); }}"
            ),
            "widening" => format!(
                "import path from 'path'; function sink(p) {{}} function run() {{ sink(path.join('a','b','c','d','{variant}')); }}"
            ),
            _ => format!("function sink(p) {{}} function run() {{ sink('{value}'); }}"),
        },
        "go" => match category {
            "negative" => format!("package main\nfunc run() int {{ return {variant} }}\n"),
            "ambiguity" | "branch" => format!(
                "package main\nfunc sink(string) {{}}\nfunc run(flag bool) {{\nif flag {{\nsink(\"{value}\")\n}} else {{\nsink(\"{second}\")\n}}\n}}\n"
            ),
            "alias" => format!(
                "package main\nfunc sink(string) {{}}\nfunc run() {{ value := \"{value}\"; sink(value) }}\n"
            ),
            "callback" => "package main\nfunc callback() {}\nfunc sink(any) {}\nfunc run() { sink(callback) }\n".into(),
            "object" => "package main\ntype Item struct{}\nfunc sink(any) {}\nfunc run() { sink(Item{}) }\n".into(),
            "collection" => format!(
                "package main\nfunc sink(any) {{}}\nfunc run() {{ sink([]string{{\"{value}\", \"{second}\"}}) }}\n"
            ),
            "return_exception" => format!(
                "package main\nimport \"errors\"\nfunc value() (string,error) {{ return \"{value}\", errors.New(\"{variant}\") }}\nfunc sink(any) {{}}\nfunc run() {{ sink(value()) }}\n"
            ),
            "widening" => format!(
                "package main\nimport \"path/filepath\"\nfunc sink(string) {{}}\nfunc run() {{ sink(filepath.Join(\"a\",\"b\",\"c\",\"d\",\"{variant}\")) }}\n"
            ),
            _ => format!(
                "package main\nfunc sink(string) {{}}\nfunc run() {{ sink(\"{value}\") }}\n"
            ),
        },
        "rust" => match category {
            "negative" => format!("fn run() -> usize {{ {variant} }}"),
            "ambiguity" | "branch" => format!(
                "fn sink(_: &str) {{}} fn run(flag: bool) {{ if flag {{ sink(\"{value}\") }} else {{ sink(\"{second}\") }} }}"
            ),
            "alias" => format!(
                "fn sink(_: &str) {{}} fn run() {{ let value = \"{value}\"; sink(value); }}"
            ),
            "callback" => "fn callback() {} fn sink<T>(_: T) {} fn run() { sink(callback); }".into(),
            "object" => "struct Item; fn sink<T>(_: T) {} fn run() { sink(Item); }".into(),
            "collection" => format!(
                "fn sink<T>(_: T) {{}} fn run() {{ sink([\"{value}\", \"{second}\"]); }}"
            ),
            "return_exception" => format!(
                "fn value() -> Result<&'static str, &'static str> {{ Ok(\"{value}\") }} fn sink<T>(_: T) {{}} fn run() {{ sink(value()); }}"
            ),
            "widening" => format!(
                "use std::path::Path; fn sink<T>(_: T) {{}} fn run() {{ sink(Path::new(\"a\").join(\"b\").join(\"c\").join(\"{variant}\")); }}"
            ),
            _ => format!("fn sink(_: &str) {{}} fn run() {{ sink(\"{value}\"); }}"),
        },
        "java" => match category {
            "negative" => format!("class App {{ static int run() {{ return {variant}; }} }}"),
            "ambiguity" | "branch" => format!(
                "class App {{ static void sink(Object p) {{}} static void run(boolean flag) {{ if (flag) sink(\"{value}\"); else sink(\"{second}\"); }} }}"
            ),
            "alias" => format!(
                "class App {{ static void sink(Object p) {{}} static void run() {{ String value = \"{value}\"; sink(value); }} }}"
            ),
            "callback" => "class App { static void callback() {} static void sink(Object p) {} static void run() { sink(App::callback); } }".into(),
            "object" => "class App { static class Item {} static void sink(Object p) {} static void run() { sink(new Item()); } }".into(),
            "collection" => format!(
                "class App {{ static void sink(Object p) {{}} static void run() {{ sink(new String[]{{\"{value}\",\"{second}\"}}); }} }}"
            ),
            "return_exception" => format!(
                "class App {{ static String value() {{ return \"{value}\"; }} static void fail() {{ throw new RuntimeException(\"{variant}\"); }} static void sink(Object p) {{}} static void run() {{ sink(value()); }} }}"
            ),
            "widening" => format!(
                "import java.nio.file.Path; class App {{ static void sink(Object p) {{}} static void run() {{ sink(Path.of(\"a\",\"b\",\"c\",\"{variant}\")); }} }}"
            ),
            _ => format!(
                "class App {{ static void sink(Object p) {{}} static void run() {{ sink(\"{value}\"); }} }}"
            ),
        },
        "ruby" => match category {
            "negative" => format!("def run; {variant}; end\n"),
            "ambiguity" | "branch" => format!(
                "def sink(p); end\ndef run(flag); if flag; sink('{value}'); else; sink('{second}'); end; end\n"
            ),
            "alias" => format!(
                "def sink(p); end\ndef run; value = '{value}'; sink(value); end\n"
            ),
            "callback" => "def callback; end\ndef sink(p); end\ndef run; sink(method(:callback)); end\n".into(),
            "object" => "class Item; end\ndef sink(p); end\ndef run; sink(Item.new); end\n".into(),
            "collection" => format!(
                "def sink(p); end\ndef run; sink(['{value}', '{second}']); end\n"
            ),
            "return_exception" => format!(
                "def value; '{value}'; end\ndef fail; raise '{variant}'; end\ndef sink(p); end\ndef run; sink(value); end\n"
            ),
            "widening" => format!(
                "def sink(p); end\ndef run; sink(File.join('a','b','c','d','{variant}')); end\n"
            ),
            _ => format!("def sink(p); end\ndef run; sink('{value}'); end\n"),
        },
        "php" => match category {
            "negative" => format!("<?php function run() {{ return {variant}; }}"),
            "ambiguity" | "branch" => format!(
                "<?php function sink($p) {{}} function run($flag) {{ if ($flag) sink('{value}'); else sink('{second}'); }}"
            ),
            "alias" => format!(
                "<?php function sink($p) {{}} function run() {{ $value = '{value}'; sink($value); }}"
            ),
            "callback" => "<?php function callback() {} function sink($p) {} function run() { sink('callback'); }".into(),
            "object" => "<?php class Item {} function sink($p) {} function run() { sink(new Item()); }".into(),
            "collection" => format!(
                "<?php function sink($p) {{}} function run() {{ sink(['{value}', '{second}']); }}"
            ),
            "return_exception" => format!(
                "<?php function value() {{ return '{value}'; }} function fail() {{ throw new Exception('{variant}'); }} function sink($p) {{}} function run() {{ sink(value()); }}"
            ),
            "widening" => format!(
                "<?php function sink($p) {{}} function run() {{ sink(join('/', ['a','b','c','d','{variant}'])); }}"
            ),
            _ => format!("<?php function sink($p) {{}} function run() {{ sink('{value}'); }}"),
        },
        "shell" => match category {
            "negative" => format!(": {variant}"),
            "ambiguity" | "branch" => {
                format!("if test -n \"$FLAG\"; then sink '{value}'; else sink '{second}'; fi")
            }
            "alias" => format!("value='{value}'; sink \"$value\""),
            "callback" => "callback() { :; }; sink callback".into(),
            "object" => format!("sink 'object:{variant}'"),
            "collection" => format!("set -- '{value}' '{second}'; sink \"$@\""),
            "return_exception" => format!("value() {{ printf '%s' '{value}'; }}; sink \"$(value)\""),
            "widening" => format!("sink a/b/c/d/{variant}"),
            _ => format!("sink '{value}'"),
        },
        _ => unreachable!(),
    }
}

fn values(summary: &ModuleSummary) -> Vec<SemanticValue> {
    summary
        .module_calls
        .iter()
        .chain(&summary.main_calls)
        .chain(
            summary
                .functions
                .iter()
                .flat_map(|function| &function.calls),
        )
        .flat_map(|edge| edge.arguments.iter().map(|argument| argument.value.clone()))
        .collect()
}

fn has_direct_effect(summary: &ModuleSummary) -> bool {
    !summary.module_effects.is_empty()
        || summary
            .functions
            .iter()
            .any(|function| !function.summary.effects.is_empty())
}

#[test]
fn compact_matrix_parses_585_named_source_fixtures() {
    let mut names = HashSet::new();
    let mut count = 0;
    for frontend in FRONTENDS {
        for category in CATEGORIES {
            for variant in 0..5 {
                let name = format!("{frontend}.{category}.{variant}");
                assert!(names.insert(name.clone()));
                let source = fixture_source(frontend, category, variant);
                if let Some((lang, file, scope)) = language(frontend) {
                    let first = module_summaries(
                        &source,
                        lang,
                        file,
                        scope.clone(),
                        &effinterp_engine::SummaryBudget::for_lang(
                            &effinterp_engine::default_limits(),
                            lang,
                        ),
                    );
                    let second = module_summaries(
                        &source,
                        lang,
                        file,
                        scope,
                        &effinterp_engine::SummaryBudget::for_lang(
                            &effinterp_engine::default_limits(),
                            lang,
                        ),
                    );
                    assert_eq!(first, second, "{name} changed across exact replay");
                    if *category == "negative" {
                        assert!(!has_direct_effect(&first), "{name} invented an effect");
                    } else {
                        assert!(
                            !first.functions.is_empty()
                                || !first.classes.is_empty()
                                || !first.module_calls.is_empty(),
                            "{name} emitted no parsed summary facts"
                        );
                    }
                } else {
                    let subject = Subject::Shell {
                        source,
                        cwd: None,
                        context: Default::default(),
                    };
                    let first = Engine::new()
                        .with_causality_detail(true)
                        .analyze(&subject)
                        .unwrap();
                    let second = Engine::new()
                        .with_causality_detail(true)
                        .analyze(&subject)
                        .unwrap();
                    assert_eq!(canonical_json(&first), canonical_json(&second), "{name}");
                    if *category == "negative" {
                        assert!(first.effects.is_empty(), "{name} invented an effect");
                    }
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 585);
    assert_eq!(names.len(), count);
}

fn first_sink_argument(source: &str, lang: Lang, file: &str, scope: ScopeKey) -> SemanticValue {
    values(&module_summaries(
        source,
        lang,
        file,
        scope,
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
    ))
    .into_iter()
    .next()
    .unwrap_or_else(|| panic!("{file} emitted no sink argument"))
}

fn direct_source(frontend: &str, literal: &str) -> String {
    match frontend {
        "python" => format!("def sink(p): pass\ndef run(): sink('{literal}')\n"),
        "javascript" => {
            format!("function sink(p) {{}} function run() {{ sink('{literal}') }}")
        }
        "typescript" => {
            format!("function sink(p: string) {{}} function run() {{ sink('{literal}') }}")
        }
        "go" => format!(
            "package main\nfunc sink(p string) {{}}\nfunc run() {{ sink(\"{literal}\") }}\n"
        ),
        "rust" => format!("fn run() {{ util::sink(\"{literal}\"); }}"),
        "java" => format!(
            "class App {{ static void sink(String p) {{}} static void run() {{ sink(\"{literal}\"); }} }}"
        ),
        "ruby" => format!("def sink(p); end\ndef run; sink('{literal}'); end\n"),
        "php" => {
            format!("<?php function sink($p) {{}} function run() {{ sink('{literal}'); }}")
        }
        _ => unreachable!(),
    }
}

fn shell_literal_value(literal: &str) -> SemanticValue {
    let (source, operation) = if literal.contains("://") {
        (format!("curl '{literal}'"), "network.request")
    } else {
        (format!("cat -- '{literal}'"), "filesystem.read")
    };
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source,
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    SemanticValue::from(
        plan.effects
            .iter()
            .find(|effect| effect.operation.0 == operation)
            .unwrap_or_else(|| panic!("shell emitted no {operation} for {literal}"))
            .resource
            .clone(),
    )
}

#[test]
fn all_frontends_canonicalize_literal_paths_urls_and_stable_ids() {
    for literal in ["/tmp/x", "data/x.txt", "hello", "https://example.test/v1"] {
        let mut observed = Vec::new();
        for frontend in FRONTENDS {
            if *frontend == "shell" {
                let first = shell_literal_value(literal);
                assert_eq!(first, shell_literal_value(literal));
                observed.push(first);
            } else {
                let source = direct_source(frontend, literal);
                let (lang, file, scope) = language(frontend).unwrap();
                let first = first_sink_argument(&source, lang, file, scope.clone());
                let replay = first_sink_argument(&source, lang, file, scope);
                assert_eq!(first, replay, "{frontend} changed its stable value IDs");
                observed.push(first);
            }
        }
        let expected = &observed[0];
        for (frontend, value) in FRONTENDS.iter().zip(&observed) {
            assert_eq!(value, expected, "{frontend} disagreed for {literal}");
            assert_eq!(value.lower_resource(), observed[0].lower_resource());
        }
    }
}

fn filesystem_effect_source(frontend: &str, literal: &str) -> String {
    match frontend {
        "python" => format!("import os\ndef run(): os.remove('{literal}')\n"),
        "javascript" => {
            format!("const fs = require('fs'); function run() {{ fs.unlinkSync('{literal}'); }}")
        }
        "typescript" => {
            format!("const fs = require('fs'); function run() {{ fs.unlinkSync('{literal}'); }}")
        }
        "go" => format!("package main\nimport \"os\"\nfunc run() {{ os.Remove(\"{literal}\") }}\n"),
        "rust" => format!("fn run() {{ std::fs::remove_file(\"{literal}\"); }}"),
        "java" => format!(
            "import java.nio.file.Files; import java.nio.file.Path; class App {{ static void run() throws Exception {{ Files.delete(Path.of(\"{literal}\")); }} }}"
        ),
        "ruby" => format!("def run; File.delete('{literal}'); end\n"),
        "php" => format!("<?php function run() {{ unlink('{literal}'); }}"),
        "shell" => format!("rm -f -- '{literal}'"),
        _ => unreachable!(),
    }
}

fn first_filesystem_effect(frontend: &str, literal: &str) -> ResourceExpr {
    let source = filesystem_effect_source(frontend, literal);
    if let Some((lang, file, scope)) = language(frontend) {
        let summary = module_summaries(
            &source,
            lang,
            file,
            scope,
            &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
        );
        summary
            .module_effects
            .iter()
            .chain(
                summary
                    .functions
                    .iter()
                    .flat_map(|function| &function.summary.effects),
            )
            .find(|effect| effect.operation.domain() == "filesystem")
            .unwrap_or_else(|| panic!("{frontend} emitted no filesystem effect"))
            .resource
            .clone()
    } else {
        Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source,
                cwd: None,
                context: Default::default(),
            })
            .unwrap()
            .effects
            .into_iter()
            .find(|effect| effect.operation.domain() == "filesystem")
            .unwrap_or_else(|| panic!("shell emitted no filesystem effect"))
            .resource
    }
}

#[test]
fn all_frontends_lower_filesystem_effects_through_the_common_value_boundary() {
    for literal in ["data/out.txt", "https://example.test/a"] {
        let expected = first_filesystem_effect("shell", literal);
        for frontend in FRONTENDS {
            assert_eq!(
                first_filesystem_effect(frontend, literal),
                expected,
                "{frontend} disagreed for {literal}"
            );
        }
    }
}

#[test]
fn widening_of_parsed_values_is_visible_and_deterministic() {
    for frontend in &FRONTENDS[..8] {
        let source = direct_source(frontend, "data/positive-4.txt");
        let (lang, file, scope) = language(frontend).unwrap();
        let mut value = first_sink_argument(&source, lang, file, scope);
        for depth in 0..12 {
            value = SemanticValue::new(SemanticValueKind::Alias {
                name: format!("level-{depth}"),
                value: Box::new(value),
            });
        }
        let canonical = value.canonicalize(ValueLimits {
            max_depth: 4,
            max_cardinality: 8,
        });
        assert!(format!("{canonical:?}").contains(&format!("{:?}", WidenReason::Depth)));
        assert_eq!(
            canonical
                .clone()
                .canonicalize(effinterp_engine::AnalysisLimits::default().value_limits()),
            canonical,
            "{frontend} widening was not stable"
        );
    }
}

fn parity_root(tag: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(tag);
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn write(root: &Path, path: &str, source: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, source).unwrap();
}

fn parity_files(marker: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "app.py",
            format!("#!/usr/bin/env python3\nimport os\nos.remove('/python')\n# {marker}\n"),
        ),
        (
            "app.js",
            format!("require('fs').unlinkSync('/javascript'); // {marker}\n"),
        ),
        (
            "app.ts",
            format!("require('fs').unlinkSync('/typescript'); // {marker}\n"),
        ),
        ("go.mod", "module example.com/matrix\n\ngo 1.21\n".into()),
        (
            "main.go",
            format!(
                "package main\nimport \"os\"\nfunc main() {{ os.Remove(\"/go\") }}\n// {marker}\n"
            ),
        ),
        (
            "main.rs",
            format!("fn main() {{ std::fs::remove_file(\"/rust\").ok(); }}\n// {marker}\n"),
        ),
        (
            "Main.java",
            format!(
                "import java.nio.file.*; class Main {{ public static void main(String[] a) throws Exception {{ Files.delete(Path.of(\"/java\")); }} }} // {marker}\n"
            ),
        ),
        (
            "app.rb",
            format!("#!/usr/bin/env ruby\nFile.delete('/ruby')\n# {marker}\n"),
        ),
        ("app.php", format!("<?php unlink('/php'); // {marker}\n")),
        ("app.sh", format!("#!/bin/sh\nrm -f /shell\n# {marker}\n")),
    ]
}

#[test]
fn nine_frontend_fixture_order_and_clean_incremental_output_are_exact() {
    let root = parity_root("p12-semantic-matrix-parity");
    let initial = parity_files("initial");
    for (path, source) in &initial {
        write(&root, path, source);
    }
    let mut incremental = build_index(&root, IndexLimits::default());

    let final_files = parity_files("perturbed");
    for (path, source) in &final_files {
        write(&root, path, source);
    }
    let mut changes: Vec<_> = final_files
        .iter()
        .map(|(path, _)| RepoChange::Modified((*path).to_string()))
        .collect();
    changes.reverse();
    apply_changes(&mut incremental, &root, &IndexLimits::default(), &changes);

    let clean = build_index(&root, IndexLimits::default());
    assert_eq!(normalize_surface(&incremental), normalize_surface(&clean));
    assert_eq!(save_index(&incremental), save_index(&clean));
    assert_eq!(
        normalize_surface(&clean),
        normalize_surface(&build_index(&root, IndexLimits::default()))
    );
}

#[test]
fn shell_process_values_use_the_common_boundary_lowering() {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "tool /tmp/x".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let resource = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "process.exec")
        .expect("shell command process effect")
        .resource
        .clone();
    let value = SemanticValue::from(resource.clone());
    assert!(matches!(value.kind, SemanticValueKind::Process { .. }));
    assert_eq!(value.lower_resource(), resource);
    assert!(matches!(
        resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { .. }
        }
    ));
}
