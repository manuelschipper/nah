//! The bounded literal frontends behind `cmd`, `lua`, `R`/`Rscript`, and
//! `julia`: what their launcher grammar reaches, what each language's literal
//! source proves, and that everything else is one boundary instead of either
//! an invented effect or a silent wall.

use std::collections::BTreeMap;

use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{
    HostContext, Plan, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
    ResourcePattern, SourceDialect, Subject, validate_plan,
};

fn plan(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/workspace/project".into()),
            context: HostContext {
                env: BTreeMap::from([("HOME".to_string(), "/home/test".to_string())]),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn source_plan(language: &str, source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            language: language.to_string(),
            dialect: None,
            source: source.to_string(),
            cwd: Some("/workspace/project".into()),
            context: HostContext {
                env: BTreeMap::from([("HOME".to_string(), "/home/test".to_string())]),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn ipython_plan(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            language: "python".to_string(),
            dialect: Some(SourceDialect::Ipython),
            source: source.to_string(),
            cwd: Some("/workspace/project".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn prime_agent_plan(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            language: "python".to_string(),
            dialect: Some(SourceDialect::PrimeAgent),
            source: source.to_string(),
            cwd: Some("/workspace/project".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn has_path(plan: &Plan, operation: &str, expected: &str) -> bool {
    paths(plan, operation).iter().any(|path| path == expected)
}

fn provenance_reaches(
    plan: &Plan,
    roots: &[ProvenanceRef],
    predicate: impl Fn(&ProvenanceKind) -> bool,
) -> bool {
    let mut pending = roots.to_vec();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let node = &plan.provenance[reference.0 as usize];
        if predicate(&node.kind) {
            return true;
        }
        pending.extend(&node.antecedents);
    }
    false
}

#[test]
fn prime_agent_bash_helper_runs_a_shell_only_while_provably_injected() {
    for source in [
        "bash('rm -rf /')",
        "print(await bash('rm -rf /'))",
        "def clean():\n    bash('rm -rf /')\nclean()",
        "(bash)('rm -rf /')",
        "print(f'bash')\nbash('rm -rf /')",
        "import re\nre.compile('x')\nbash('rm -rf /')",
        "\u{ff42}\u{ff41}\u{ff53}\u{ff48}('rm -rf /')",
        "class Base:\n    pass\nclass Job(Base):\n    bash('rm -rf /')",
    ] {
        assert!(
            has_path(&prime_agent_plan(source), "filesystem.delete", "/"),
            "{source}"
        );
    }
    for source in [
        "bash = print\nbash('rm -rf /')",
        "bash('rm -rf /')\ndel bash",
        "def run(bash):\n    bash('rm -rf /')\nrun(print)",
        "from helpers import bash\nbash('rm -rf /')",
        "from helpers import *\nbash('rm -rf /')",
        "run = bash\nbash('rm -rf /')",
        "globals()['bash'] = print\nbash('rm -rf /')",
        "exec(source)\nbash('rm -rf /')",
        "f'{(bash := print)}'\nbash('rm -rf /')",
        "globals().update({'bash': print})\nbash('rm -rf /')",
        "globals().__setitem__('bash', print)\nbash('rm -rf /')",
        "locals().update({'bash': print})\nbash('rm -rf /')",
        "namespace = globals()\nnamespace['bash'] = print\nbash('rm -rf /')",
        "import sys\nsys.modules['__main__'].__setattr__('bash', print)\nbash('rm -rf /')",
        // Python binds identifiers after NFKC normalization.
        "\u{ff42}\u{ff41}\u{ff53}\u{ff48} = print\nbash('rm -rf /')",
        "def run(\u{ff42}\u{ff41}\u{ff53}\u{ff48}):\n    bash('rm -rf /')\nrun(print)",
        // An alias renames a namespace facility without changing what it reaches.
        "import builtins as b\nb.exec('bash = print')\nbash('rm -rf /')",
        "from builtins import exec as run\nrun('bash = print')\nbash('rm -rf /')",
        // Reflection reaches `__globals__` through a string.
        "def f(): pass\ngetattr(f, '__globals__')['bash'] = print\nbash('rm -rf /')",
        "f = lambda: None\nf.__class__.__getattribute__(f, '__globals__')['bash'] = print\nbash('rm -rf /')",
        "f = lambda: None\ntype(f).__getattribute__(f, '__globals__')['bash'] = print\nbash('rm -rf /')",
        "def mark(f):\n    getattr(f, '__globals__')['bash'] = print\n    return f\n@mark\ndef g(): pass\nbash('rm -rf /')",
        // A metaclass's `__prepare__` supplies the class body's names.
        "class Meta(type):\n    @classmethod\n    def __prepare__(mcls, name, bases):\n        return {'bash': print}\nclass C(metaclass=Meta):\n    bash('rm -rf /')",
        "Meta = type('Meta', (type,), {'__prepare__': classmethod(lambda *a: {'bash': print})})\nclass C(metaclass=Meta):\n    bash('rm -rf /')",
        "from models import Base\nclass Job(Base):\n    bash('rm -rf /')",
        "!rm -rf /",
    ] {
        assert!(
            !has_path(&prime_agent_plan(source), "filesystem.delete", "/"),
            "{source}"
        );
    }
    // Plain Python gives the name no meaning.
    assert!(!has_path(
        &source_plan("python", "bash('rm -rf /')"),
        "filesystem.delete",
        "/"
    ));
}

#[test]
fn ipython_shell_cell_and_call_forms_reach_their_nested_frontends() {
    for source in [
        "!rm -rf /",
        "!!rm -rf /",
        "%system rm -rf /",
        "%sx rm -rf /",
        "%sc rm -rf /",
        "%%bash -e\nrm -rf /",
        "%%sh\nrm -rf /",
        "%%script bash --noprofile\nrm -rf /",
        "get_ipython().system('rm -rf /')",
        "get_ipython().getoutput('rm -rf /')",
        "get_ipython().run_line_magic('system', 'rm -rf /')",
        "get_ipython().run_cell_magic('bash', '-e', 'rm -rf /')",
    ] {
        let plan = ipython_plan(source);
        assert!(
            has_path(&plan, "filesystem.delete", "/"),
            "{source}: {:?}",
            plan.effects
        );
    }

    let script = ipython_plan("%%script python\nimport os; os.remove('/tmp/from-script')");
    assert!(has_path(&script, "filesystem.delete", "/tmp/from-script"));

    let source = "%%bash -e\nrm -rf /";
    let plan = ipython_plan(source);
    let deletion = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    let body_start = source.find("rm -rf /").unwrap() as u32;
    assert!(provenance_reaches(
        &plan,
        &deletion.provenance,
        |kind| matches!(kind, ProvenanceKind::SourceSpan { start, .. } if *start >= body_start)
    ));

    let symbolic = ipython_plan("get_ipython().system(prior)");
    assert!(!has_path(&symbolic, "filesystem.delete", "/"));
    assert!(symbolic.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("unresolved word: prior"))
    }));

    for source in [
        "get_ipython = replacement\nget_ipython().system('rm -rf /')",
        "del get_ipython\nget_ipython().system('rm -rf /')",
        "get_ipython().system = replacement\nget_ipython().system('rm -rf /')",
        "shell = get_ipython()\nshell.system('rm -rf /')",
    ] {
        assert!(
            !has_path(&ipython_plan(source), "filesystem.delete", "/"),
            "{source}"
        );
    }
}

#[test]
fn ipython_interpolation_uses_only_current_cell_literal_bindings() {
    for source in [
        "target='/'\n!rm -rf {target}",
        "prefix=''\ntarget='/'\n!rm -rf {prefix + target}",
        "target='/'\n!rm -rf $target",
        "target='/'\n!rm -rf ${target}",
    ] {
        let plan = ipython_plan(source);
        assert!(
            has_path(&plan, "filesystem.delete", "/"),
            "{source}: {:?}",
            plan.effects
        );
    }

    for source in ["!rm -rf {prior}", "!rm -rf $prior", "!rm -rf ${prior}"] {
        let plan = ipython_plan(source);
        assert!(
            plan.boundaries.iter().any(|boundary| boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("unresolved word: prior"))),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(!has_path(&plan, "filesystem.delete", "/"), "{source}");
    }
}

#[test]
fn ipython_stateful_magics_apply_in_cell_order() {
    let changed = ipython_plan("%cd /; !rm -rf .");
    assert!(has_path(&changed, "filesystem.delete", "/"));

    let write = ipython_plan("%%writefile -a output.txt\nreplacement");
    assert!(has_path(
        &write,
        "filesystem.write",
        "/workspace/project/output.txt"
    ));

    let environment = ipython_plan("%env MODE=production\n!printenv MODE");
    assert!(environment.execution_graph.nodes.iter().any(|node| {
        node.environment.get("MODE")
            == Some(&Some(ResourceExpr::Literal {
                value: "production".to_string(),
            }))
    }));

    for source in [
        "%pip install demo",
        "%conda remove demo",
        "!pip uninstall demo",
    ] {
        let plan = ipython_plan(source);
        assert!(
            plan.execution_graph
                .nodes
                .iter()
                .any(|node| match &node.subject {
                    Subject::Exec { argv, .. } => argv
                        .first()
                        .is_some_and(|program| matches!(program.as_str(), "pip" | "conda")),
                    _ => false,
                }),
            "{source}"
        );
    }
}

#[test]
fn ipython_output_magics_are_transparent_and_unknown_magics_are_explicit() {
    for source in [
        "%load ignored.py\nimport os; os.remove('/tmp/loaded-cell')",
        "%history\nimport os; os.remove('/tmp/history-cell')",
        "%matplotlib inline\nimport os; os.remove('/tmp/matplotlib-cell')",
        "%load_ext autoreload\n%autoreload 2\nimport os; os.remove('/tmp/extension-cell')",
        "%time import os; os.remove('/tmp/timed-line')",
        "%%time\nimport os; os.remove('/tmp/timed-cell')",
        "%%timeit\nimport os; os.remove('/tmp/timed-repeat')",
        "%%capture\nimport os; os.remove('/tmp/captured-cell')",
    ] {
        let plan = ipython_plan(source);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{source}"
        );
        assert!(
            plan.boundaries.iter().all(|boundary| {
                boundary.reason != effinterp_proto::BoundaryReason::new("unknown_ipython_magic")
            }),
            "{source}"
        );
    }

    let unknown = ipython_plan("%mystery value");
    assert!(unknown.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::new("unknown_ipython_magic")
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("%mystery"))
    }));

    let unknown_option = ipython_plan("%%bash --mystery\nrm -rf /");
    assert!(has_path(&unknown_option, "filesystem.delete", "/"));
    assert!(unknown_option.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("--mystery"))
    }));
}

struct IpythonSources(BTreeMap<String, String>);

impl SourceResolver for IpythonSources {
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0.get(request.path).map_or(
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            |source| SourceResponse::Source(source.as_bytes().to_vec()),
        )
    }

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        Some(
            self.0
                .keys()
                .filter(|candidate| {
                    candidate
                        .rsplit_once('/')
                        .map_or("", |(candidate_parent, _)| candidate_parent)
                        == parent
                })
                .cloned()
                .collect(),
        )
    }
}

#[test]
fn ipython_run_demands_and_analyzes_the_selected_python_script() {
    let plan = Engine::new()
        .with_resolver(Box::new(IpythonSources(BTreeMap::from([(
            "/workspace/project/evil.py".to_string(),
            "import os; os.remove('/tmp/from-run')".to_string(),
        )]))))
        .analyze(&Subject::Source {
            language: "python".to_string(),
            dialect: Some(SourceDialect::Ipython),
            source: "%run evil.py argument".to_string(),
            cwd: Some("/workspace/project".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has_path(
        &plan,
        "filesystem.read",
        "/workspace/project/evil.py"
    ));
    assert!(has_path(&plan, "filesystem.delete", "/tmp/from-run"));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.input
            .as_ref()
            .and_then(|input| input.selected.as_ref())
            == Some(&ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/workspace/project/evil.py".to_string(),
                },
            })
    }));
}

#[test]
fn r_content_apis_state_access_purpose_and_transfer() {
    let write = plan(r#"R -e 'writeLines("x", "/home/test/.nah/trust.json")'"#);
    assert_eq!(
        write
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap()
            .attributes
            .get("disclosure"),
        Some(&effinterp_proto::AttrValue::String("contents".into()))
    );

    let copy = plan(r#"R -e 'file.copy("/tmp/replacement", "/home/test/.nah/trust.json")'"#);
    assert_eq!(
        copy.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap()
            .attributes
            .get("access_purpose"),
        Some(&effinterp_proto::AttrValue::String("program_input".into()))
    );
    assert_eq!(
        copy.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap()
            .attributes
            .get("disclosure"),
        Some(&effinterp_proto::AttrValue::String("contents".into()))
    );
    assert!(
        copy.causality
            .graph
            .as_ref()
            .unwrap()
            .edges
            .iter()
            .any(|edge| {
                edge.reason == effinterp_proto::CausalReason::ResourceTransfer
                    && edge.assurance == effinterp_proto::CausalAssurance::Exact
            })
    );
}

#[test]
fn comments_and_long_strings_cannot_turn_quoted_mutations_into_effects() {
    for (language, source, domains) in [
        (
            "lua",
            "--[[\nos.remove(\"/home/test/.nah/trust.json\")\n]]",
            &["environment", "filesystem", "process"][..],
        ),
        (
            "lua",
            "print([[os.remove(\"/home/test/.nah/trust.json\")]])",
            &["environment", "filesystem", "process"][..],
        ),
        (
            "julia",
            "#=\nrm(\"/home/test/.nah/trust.json\")\n=#",
            &["environment", "filesystem", "process"][..],
        ),
        (
            "perl",
            "=pod\nunlink '/home/test/.local/bin/nah';\n=cut",
            &["filesystem", "process"][..],
        ),
        (
            "ruby",
            "=begin\nFile.unlink('/home/test/.nah/trust.json')\n=end",
            &["environment", "filesystem", "network", "process"][..],
        ),
        (
            "ruby",
            "puts %q{File.unlink(\"/home/test/.nah/trust.json\")}",
            &["environment", "filesystem", "network", "process"][..],
        ),
    ] {
        let plan = source_plan(language, source);
        assert!(
            plan.effects
                .iter()
                .all(|effect| !effect.operation.0.starts_with("filesystem.")),
            "{language}: {:?}",
            plan.effects
        );
        assert!(
            plan.boundaries.is_empty(),
            "{language}: {:?}",
            plan.boundaries
        );
        for domain in domains {
            assert!(
                plan.coverage
                    .is_full(&effinterp_proto::Domain::new(*domain)),
                "{language}: {domain}: {:?}",
                plan.coverage
            );
        }
    }
}

fn paths(plan: &Plan, operation: &str) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.0 == operation)
        .map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => path.clone(),
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { glob, .. },
            } => format!("glob:{glob}"),
            other => effinterp_proto::display_resource(other),
        })
        .collect()
}

#[test]
fn literal_interpreter_source_resolves_through_each_language_escape_and_environment_rule() {
    let trust = "/home/test/.nah/trust.json";
    for (source, operation, expected) in [
        // Lua decimal and hexadecimal escapes, concatenation, os.getenv.
        (
            r#"lua -e 'os.remove("/home/test/\046nah/trust.json")'"#,
            "filesystem.delete",
            trust,
        ),
        (
            r#"lua -e 'os.remove("\x2fhome/test/.nah/trust.json")'"#,
            "filesystem.delete",
            trust,
        ),
        (
            r#"lua -e 'io.open(os.getenv("HOME").."/.nah/trust.json", "w")'"#,
            "filesystem.write",
            trust,
        ),
        // A literal load chunk is source, not an opaque value.
        (
            r#"lua -e 'load("os.remove(\"/home/test/.nah/trust.json\")")()'"#,
            "filesystem.delete",
            trust,
        ),
        (
            r#"luajit -e 'os.rename("/home/test/.nah/trust.json", "/tmp/x")'"#,
            "filesystem.move",
            trust,
        ),
        // R binds `con` by name or position and expands `~` through HOME.
        (
            r#"R -e 'writeLines("x", "/home/test/.nah/trust.json")'"#,
            "filesystem.write",
            trust,
        ),
        (
            r#"R -e 'cat("x", file = "~/.nah/trust.json")'"#,
            "filesystem.write",
            trust,
        ),
        (
            r#"R -e 'file.remove(file.path(Sys.getenv("HOME"), ".nah", "trust.json"))'"#,
            "filesystem.delete",
            trust,
        ),
        (
            r#"Rscript -e'file.remove("/home/test/.nah/trust.json")'"#,
            "filesystem.delete",
            trust,
        ),
        // Julia keyword arguments, joinpath, and string interpolation.
        (
            r#"julia --eval 'rm("/home/test/.nah/trust.json")'"#,
            "filesystem.delete",
            trust,
        ),
        (
            r#"julia -e 'write(joinpath(homedir(), ".nah/trust.json"), "x")'"#,
            "filesystem.write",
            trust,
        ),
        (
            r#"julia -E 'cp("/tmp/replacement", "$(ENV["HOME"])/.nah/trust.json")'"#,
            "filesystem.write",
            trust,
        ),
        // cmd takes its command string from the raw line, attached or not.
        (
            "cmd /Cdel '/home/test/.nah/trust.json'",
            "filesystem.delete",
            trust,
        ),
        (
            "cmd /c 'del %HOME%/.nah/trust.json'",
            "filesystem.delete",
            trust,
        ),
        (
            "cmd /q /c 'copy /tmp/replacement /home/test/.nah/trust.json'",
            "filesystem.write",
            trust,
        ),
        (
            "cmd /c 'type /tmp/replacement > /home/test/.nah/trust.json'",
            "filesystem.write",
            trust,
        ),
        // A drive-qualified operand resolves in the Windows dialect.
        (
            "cmd /c 'rd /s /q C:\\Users\\test'",
            "filesystem.delete",
            "C:/Users/test",
        ),
        // A caret before the line terminator continues the command line.
        (
            "cmd /c 'del /q ^\nC:\\Users\\test\\secret.txt'",
            "filesystem.delete",
            "C:/Users/test/secret.txt",
        ),
    ] {
        let plan = plan(source);
        assert!(
            paths(&plan, operation).contains(&expected.to_string()),
            "{source}: {operation} {:?}",
            paths(&plan, operation)
        );
    }
}

#[test]
fn recursive_and_wildcard_selectors_keep_their_shape() {
    let recursive = plan("cmd /c 'rd /s /q /home/test/.nah'");
    assert_eq!(paths(&recursive, "filesystem.delete"), ["/home/test/.nah"]);
    assert_eq!(
        recursive.effects[recursive.effects.len() - 1].attributes["recursive"],
        effinterp_proto::AttrValue::Bool(true)
    );
    let wildcard = plan("cmd /c 'del /q /home/test/.nah/*'");
    assert_eq!(
        paths(&wildcard, "filesystem.delete"),
        ["glob:/home/test/.nah/*"]
    );
    assert_eq!(
        wildcard
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("cmd wildcard delete")
            .request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    // `unlink` is the one R file function that expands wildcards itself.
    assert_eq!(
        paths(
            &plan(r#"R -e 'unlink("/home/test/.nah/*", recursive = TRUE)'"#),
            "filesystem.delete"
        ),
        ["glob:/home/test/.nah/*"]
    );
    assert_eq!(
        paths(
            &plan(r#"R -e 'file.remove("/home/test/.nah/*")'"#),
            "filesystem.delete"
        ),
        ["/home/test/.nah/*"]
    );
}

/// Whether the nested `sh -c` child whose source mentions `/tmp/doomed` writes
/// to the program's own stdout, rather than into a captured value. The
/// outermost shell mentions it too, so the innermost node is the child.
fn doomed_child_inherits_stdout(plan: &Plan) -> bool {
    plan.execution_graph
        .nodes
        .iter()
        .rev()
        .find(|node| {
            matches!(&node.subject, Subject::Shell { source, .. } if source.contains("/tmp/doomed"))
        })
        .expect("a shell child runs the command")
        .streams
        .stdout
        .is_some()
}

#[test]
fn lua_os_execute_and_io_popen_run_shell_source_in_call_order() {
    // `io.popen` reads the child's output unless its mode is "w".
    for (source, inherits_stdout) in [
        (r#"lua -e 'os.execute("rm -rf /tmp/doomed")'"#, true),
        (r#"lua -e 'io.popen("rm -rf /tmp/doomed")'"#, false),
        (r#"lua -e 'io.popen("rm -rf /tmp/doomed", "r")'"#, false),
        (r#"lua -e 'io.popen("rm -rf /tmp/doomed", "w")'"#, true),
        // Replacing the namespace afterwards cannot undo the earlier call.
        (
            r#"lua -e 'os.execute("rm -rf /tmp/doomed"); os = {}'"#,
            true,
        ),
        // A called function's body runs where it is called.
        (
            "lua -e 'local function f()\n  io.popen(\"rm -rf /tmp/doomed\")\nend\nf()'",
            false,
        ),
        (
            r#"lua -e 'function g() os.execute("rm -rf /tmp/doomed") end function f() g() end f()'"#,
            true,
        ),
        // A local replacement ends with its function's block, and a local
        // declared after a definition is not visible inside it.
        (
            r#"lua -e 'function f() local os = {} end f(); os.execute("rm -rf /tmp/doomed")'"#,
            true,
        ),
        (
            r#"lua -e 'function f() os.execute("rm -rf /tmp/doomed") end; local os = {}; f()'"#,
            true,
        ),
        // Parameters are bound to the call's arguments, through nested calls.
        (
            r#"lua -e 'function f(p, flag) os.execute("rm " .. flag .. " " .. p) end f("/tmp/doomed", "-rf")'"#,
            true,
        ),
        (
            r#"lua -e 'function g(c) os.execute(c) end function f(d) g("rm -rf " .. d) end f("/tmp/doomed")'"#,
            true,
        ),
    ] {
        let plan = plan(source);
        assert_eq!(
            doomed_child_inherits_stdout(&plan),
            inherits_stdout,
            "{source}"
        );
        assert!(
            has_path(&plan, "filesystem.delete", "/tmp/doomed"),
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    for source in [
        r#"lua -e 'local io = {}; io.popen("rm -rf /tmp/doomed")'"#,
        r#"lua -e 'function f() os.execute("rm -rf /tmp/doomed") end f = {}; f()'"#,
        // A local function is gone once its enclosing call returns.
        r#"lua -e 'function f() local function g() os.execute("rm -rf /tmp/doomed") end end f(); g()'"#,
        // A call stopped at the nesting limit never returns to its caller.
        r#"lua -e 'function f() f(); os.execute("rm -rf /tmp/doomed") end f()'"#,
        // A missing argument, a name no parameter binds, and a parameter
        // shadowing the library each end in a boundary.
        r#"lua -e 'function f(p) os.execute("rm -rf " .. p) end f()'"#,
        r#"lua -e 'function f(p) os.execute("rm -rf " .. q) end f("/tmp/doomed")'"#,
        r#"lua -e 'function f(os) os.execute("rm -rf /tmp/doomed") end f("x")'"#,
    ] {
        let plan = plan(source);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn r_system_and_system2_run_shell_source() {
    // `intern = TRUE` returns the output as a value instead of printing it.
    for (source, inherits_stdout) in [
        (r#"Rscript -e 'system("rm -rf /tmp/doomed")'"#, true),
        (
            r#"Rscript -e 'system("rm -rf /tmp/doomed", intern=TRUE, ignore.stdout=TRUE)'"#,
            false,
        ),
        (
            r#"Rscript -e 'system("rm -rf /tmp/doomed", intern=TRUE)'"#,
            false,
        ),
        (r#"Rscript -e 'system(command="rm -rf /tmp/doomed")'"#, true),
        // `system2` quotes the command but pastes `args` in as shell text.
        (r#"Rscript -e 'system2("rm", "-rf /tmp/doomed")'"#, true),
        (
            r#"Rscript -e 'system2("rm", args="-rf /tmp/doomed", wait=FALSE)'"#,
            true,
        ),
    ] {
        let plan = plan(source);
        assert_eq!(
            doomed_child_inherits_stdout(&plan),
            inherits_stdout,
            "{source}"
        );
        assert!(
            has_path(&plan, "filesystem.delete", "/tmp/doomed"),
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    for source in [
        // An argument vector, an input stream, or an unrecoverable operand.
        r#"Rscript -e 'system2("rm", c("-rf", "/tmp/doomed"))'"#,
        r#"Rscript -e 'system("sh", input="rm -rf /tmp/doomed")'"#,
        r#"Rscript -e 'system(cmd, "rm -rf /tmp/doomed")'"#,
        r#"Rscript -e 'system2(cmd, "rm -rf /tmp/doomed")'"#,
    ] {
        let plan = plan(source);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn r_bindings_and_named_x_feed_later_calls() {
    for source in [
        r#"Rscript -e 'd <- "/tmp/doomed"; unlink(d, recursive=TRUE)'"#,
        r#"Rscript -e 'unlink(x="/tmp/doomed", recursive=TRUE)'"#,
        r#"Rscript -e 'cmd <- paste0("rm -rf ", "/tmp/doomed"); system(cmd)'"#,
    ] {
        let plan = plan(source);
        assert!(
            has_path(&plan, "filesystem.delete", "/tmp/doomed"),
            "{source}"
        );
        assert!(plan.boundaries.is_empty(), "{source}");
    }
    // A function binding, or a global `<<-` one, is outside the grammar.
    for source in [
        r#"Rscript -e 'system <- function(...) NULL; system("rm -rf /tmp/doomed")'"#,
        r#"Rscript -e 'd <<- "/tmp/doomed"; unlink(d, recursive=TRUE)'"#,
    ] {
        let plan = plan(source);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn r_eval_parse_text_runs_literal_source_in_the_same_program() {
    let plan = plan(
        r#"Rscript -e 'd <- "/tmp/doomed"; eval(parse(text="unlink(d); file.remove(\"/tmp/other\")"))'"#,
    );
    assert_eq!(
        paths(&plan, "filesystem.delete"),
        ["/tmp/doomed", "/tmp/other"]
    );
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    let file = self::plan(r#"Rscript -e 'eval(parse(file="/tmp/x.R"))'"#);
    assert!(paths(&file, "filesystem.delete").is_empty());
    assert!(!file.boundaries.is_empty());
}

#[test]
fn julia_function_definitions_run_only_where_called() {
    let called = plan("julia -e 'function f()\n  rm(\"/tmp/doomed\"; recursive=true)\nend\nf()'");
    assert_eq!(paths(&called, "filesystem.delete"), ["/tmp/doomed"]);
    assert!(called.boundaries.is_empty(), "{:?}", called.boundaries);
    let uncalled = plan("julia -e 'function f(); rm(\"/tmp/doomed\"); end'");
    assert!(paths(&uncalled, "filesystem.delete").is_empty());
    assert!(uncalled.boundaries.is_empty(), "{:?}", uncalled.boundaries);
    for source in [
        // Defining `rm` shadows Base.rm; parameters and recursion are unmodeled.
        "julia -e 'function rm()\nend\nrm(\"/tmp/doomed\")'",
        "julia -e 'function f(p)\n  rm(p)\nend\nf(\"/tmp/doomed\")'",
        "julia -e 'function f()\n  f()\nend\nf()'",
        // A nested block cannot close the function early.
        "julia -e 'function f()\n  open(\"/tmp/x\") do io\n  end\n  rm(\"/tmp/doomed\")\nend'",
    ] {
        let plan = plan(source);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn julia_eval_meta_parse_runs_one_literal_statement() {
    let plan = plan(r#"julia -e 'eval(Meta.parse("rm(\"/tmp/doomed\")"))'"#);
    assert_eq!(paths(&plan, "filesystem.delete"), ["/tmp/doomed"]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    let two = self::plan(r#"julia -e 'eval(Meta.parse("rm(\"/tmp/a\"); rm(\"/tmp/b\")"))'"#);
    assert!(paths(&two, "filesystem.delete").is_empty());
    assert!(!two.boundaries.is_empty());
}

#[test]
fn julia_run_command_literal_executes_its_exact_argv() {
    for source in [
        "julia -e 'run(`rm -rf /tmp/doomed`)'",
        r#"julia -e 'run(`rm -rf "/tmp/doomed"`; wait=false)'"#,
        "julia -e 'run(`rm -rf /tmp/doo\\med`)'",
    ] {
        let plan = plan(source);
        assert!(
            has_path(&plan, "filesystem.delete", "/tmp/doomed"),
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    // Words are never shell source: `;` must be quoted and then is an operand.
    let quoted = plan("julia -e 'run(`echo \";\" rm -rf /tmp/doomed`)'");
    assert!(paths(&quoted, "filesystem.delete").is_empty());
    for source in [
        "julia -e 'run(`rm -rf $target`)'",
        "julia -e 'run(`rm -rf /tmp/doomed; true`)'",
        "julia -e 'run(pipeline(`rm -rf /tmp/doomed`))'",
    ] {
        let plan = plan(source);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
}

#[test]
fn an_unmodeled_construct_is_one_boundary_and_never_an_invented_effect() {
    for source in [
        // Lua: control flow, declarations, bindings, and receiver values.
        r#"lua -e 'if x then os.remove("/home/test/.nah/trust.json") end'"#,
        r#"lua -e 'function f() os.remove("/home/test/.nah/trust.json") end'"#,
        r#"lua -e 'local p = "/home/test/.nah/trust.json"; os.remove(p)'"#,
        r#"lua -e 'os = {}; os.execute("rm /home/test/.nah/trust.json")'"#,
        r#"lua -e 'os == x; os.execute("rm /home/test/.nah/trust.json")'"#,
        r#"lua -e 'dofile("/tmp/chunk.lua")'"#,
        r#"lua -e 'io.open("/home/test/.nah/trust.json", mode)'"#,
        // R: control flow, shell escapes, and runtime-selected source.
        r#"R -e 'if (TRUE) unlink("/home/test/.nah/trust.json")'"#,
        r#"R -e 'system2("rm", c("/home/test/.nah/trust.json"))'"#,
        r#"R -e 'source("/tmp/script.R")'"#,
        r#"R -e 'unlink(target)'"#,
        // Julia: loops, command literals, and runtime-selected source.
        r#"julia -e 'for f in x; rm(f); end'"#,
        r#"julia -e 'run(`rm $(target)/.nah/trust.json`)'"#,
        r#"julia -e 'include("/tmp/script.jl")'"#,
        r#"julia -e 'rm("$(target)/.nah/trust.json")'"#,
        // cmd: blocks, delayed expansion, and unmodeled commands.
        "cmd /c 'dir /home/test/.nah'",
        "cmd /c 'del /z /home/test/.nah/trust.json'",
        "cmd /c 'for %f in (*) do del %f'",
        // A share on another host has no canonical path form of its own.
        "cmd /c 'del \\\\host\\share\\trust.json'",
    ] {
        let plan = plan(source);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("filesystem.")),
            "{source} invented {:?}",
            plan.effects
                .iter()
                .map(|effect| effect.operation.0.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            plan.boundaries.iter().any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
                && !boundary.provenance.is_empty()),
            "{source} has no boundary naming the construct"
        );
    }
}

#[test]
fn launcher_grammar_reaches_only_the_options_that_supply_source() {
    // `R` runs no bare operand as a program, so nothing is nested for one.
    let operand = plan("R --vanilla script.R");
    assert!(
        operand
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
    assert!(
        operand
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE })
    );
    // Arguments after `--args` are data, not options.
    let args = plan(r#"R --slave -e 'unlink("/home/test/.nah/trust.json")' --args -e other"#);
    assert_eq!(
        paths(&args, "filesystem.delete"),
        ["/home/test/.nah/trust.json"]
    );
    assert!(args.boundaries.iter().all(|boundary| {
        boundary.detail.as_deref() != Some("R operand does not select a program")
    }));
    // An interactive cmd or R session supplies no command string.
    for source in ["cmd", "cmd /q", "R --no-save"] {
        let plan = plan(source);
        assert!(
            plan.effects
                .iter()
                .all(|effect| !effect.operation.0.starts_with("filesystem."))
        );
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE
            }),
            "{source}"
        );
    }
    // Repeated inline-source options leave the unanalyzed ones explicit.
    let repeated = plan(r#"lua -e 'os.remove("/tmp/a")' -e 'os.remove("/tmp/b")'"#);
    assert_eq!(paths(&repeated, "filesystem.delete"), ["/tmp/b"]);
    assert!(repeated.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("repetitions"))
    }));
}

#[test]
fn a_source_larger_than_the_limit_saturates_instead_of_reporting_a_partial_walk() {
    for language in ["cmd", "lua", "r", "julia"] {
        let mut limits = effinterp_engine::AnalysisLimits::default().to_map();
        limits.insert("max_source_bytes".into(), 4);
        let plan = Engine::with_limits(limits)
            .unwrap()
            .analyze(&Subject::Source {
                language: language.into(),
                dialect: None,
                source: "del /home/test/.nah/trust.json".into(),
                cwd: Some("/workspace/project".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.effects.is_empty(), "{language}");
        assert_eq!(plan.boundaries.len(), 1, "{language}");
        assert_eq!(
            plan.boundaries[0].limit.as_deref(),
            Some("max_source_bytes"),
            "{language}"
        );
    }
}

// ---- python / ipython

#[test]
fn ipython_launcher_runs_its_c_cell_as_ipython() {
    for source in [
        "ipython -c '!rm -rf /srv'",
        "ipython3 --no-banner -c '%%bash\nrm -rf /srv'",
        r#"ipython -c 'import shutil; shutil.rmtree("/srv")'"#,
    ] {
        let plan = plan(source);
        assert!(
            has_path(&plan, "filesystem.delete", "/srv"),
            "{source}: {:?}",
            plan.effects
        );
    }
    // Help exits before the cell runs, and a script stays opaque.
    assert!(
        paths(
            &plan("ipython --help -c '!rm -rf /srv'"),
            "filesystem.delete"
        )
        .is_empty()
    );
    let script = plan("ipython cell.ipy");
    assert!(
        script
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE })
    );
}

#[test]
fn pypy_launchers_run_inline_python() {
    for launcher in ["pypy", "pypy3"] {
        let plan = plan(&format!(
            r#"{launcher} -c 'import os; os.remove("/tmp/a")'"#
        ));
        assert!(has_path(&plan, "filesystem.delete", "/tmp/a"), "{launcher}");
    }
}
