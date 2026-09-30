//! Python cross-module extraction: a file's per-function summaries, its
//! call edges, and its import bindings.

use effinterp_engine::{
    Lang, ModuleSummary, ObjectIdentity, ScopeKey, SemanticValueKind, TypeRef, module_summaries,
};
use effinterp_proto::{ResourceExpr, ResourceIdentity};

fn extract(src: &str) -> ModuleSummary {
    module_summaries(
        src,
        Lang::Python,
        "pkg/mod.py",
        ScopeKey::Module {
            key: "pkg.mod".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Python,
        ),
    )
}

fn func<'a>(m: &'a ModuleSummary, name: &str) -> &'a effinterp_engine::FunctionEntry {
    m.functions
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"))
}

#[test]
fn callable_defaults_and_external_factory_returns_keep_exact_identity() {
    let module = extract(
        "import requests\nfrom parser import HTTPieArgumentParser\ndef to_argparse(parser_type=HTTPieArgumentParser):\n    return parser_type()\ndef build_session():\n    session = requests.Session()\n    return session\n",
    );
    assert_eq!(
        func(&module, "to_argparse").callable_defaults,
        vec![Some("HTTPieArgumentParser".to_string())]
    );
    let session = func(&module, "build_session");
    assert_eq!(
        session.return_types,
        vec![Some(TypeRef::External {
            path: "requests.Session".to_string(),
        })]
    );
}

fn summary_process_cwd<'a>(
    module: &'a ModuleSummary,
    function: &str,
    executable: &str,
) -> &'a ResourceExpr {
    func(module, function)
        .summary
        .effects
        .iter()
        .find_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable: name,
                        cwd: Some(cwd),
                        ..
                    },
            } if name == executable => Some(cwd.as_ref()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {executable} cwd in {function}"))
}

#[test]
fn subprocess_summary_retains_symbolic_and_file_backed_cwd() {
    let parameter = extract(
        "import subprocess\ndef launch(root):\n    subprocess.run(['git', 'status'], cwd=root)\n",
    );
    assert!(matches!(
        summary_process_cwd(&parameter, "launch", "git"),
        ResourceExpr::Parameter { name } if name == "root"
    ));

    let joined = extract(
        "from pathlib import Path\nimport subprocess\ndef launch(root):\n    subprocess.run(['git', 'status'], cwd=Path(root, 'checkout'))\n",
    );
    assert!(matches!(
        summary_process_cwd(&joined, "launch", "git"),
        ResourceExpr::Join { parts }
            if matches!(&parts[0], ResourceExpr::Parameter { name } if name == "root")
                && matches!(&parts[1], ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "checkout")
    ));

    let source = "from pathlib import Path\nfrom subprocess import check_call\nROOT_SRC_DIR = Path(__file__).parents[1]\ndef release():\n    check_call(['gh', 'release'], cwd=str(ROOT_SRC_DIR))\n";
    let module = module_summaries(
        source,
        Lang::Python,
        "tasks/release.py",
        ScopeKey::Module {
            key: "tasks.release".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Python,
        ),
    );
    assert!(matches!(
        summary_process_cwd(&module, "release", "gh"),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path.is_empty()
    ));
}

#[test]
fn return_summary_uses_function_local_path_values() {
    let module = extract(concat!(
        "from pathlib import Path\n",
        "def cache_dir():\n",
        "    root = Path.home()\n",
        "    cache = root / '.cache' / 'tool'\n",
        "    return cache\n",
    ));
    assert!(matches!(
        func(&module, "cache_dir").summary.returns.as_ref().map(|value| value.lower_resource()),
        Some(ResourceExpr::Join { parts })
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: cache }
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: tool }
                }
            ] if name == "HOME" && cache == ".cache" && tool == "tool")
    ));
}

#[test]
fn return_summary_preserves_symbolic_concatenation_parts() {
    let module = extract("def repeat(path):\n    return path + path + path + path\n");
    let resource = func(&module, "repeat")
        .summary
        .returns
        .as_ref()
        .expect("repeat has a return summary")
        .lower_resource();
    let ResourceExpr::Join { parts } = resource else {
        panic!("expected a symbolic join, got {resource:?}");
    };
    assert_eq!(parts.len(), 4);
    assert!(
        parts
            .iter()
            .all(|part| matches!(part, ResourceExpr::Parameter { name } if name == "path"))
    );
}

#[test]
fn summary_string_constant_is_not_preanchored_inside_a_join() {
    let module = extract(
        "import os\nUSER = 'alice'\ndef remove_log():\n    os.remove('/home/' + USER + '/logs/app.log')\n",
    );
    let delete = func(&module, "remove_log")
        .summary
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("remove_log delete");
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == "/home/alice/logs/app.log"
    ));
}

#[test]
fn path_method_on_constructor_attribute_stays_symbolic_in_summary() {
    let module = extract(concat!(
        "class Rel:\n",
        "    def __init__(self, path):\n",
        "        self.path = path\n",
        "    def go(self):\n",
        "        self.path.read_text()\n",
    ));
    let read = func(&module, "Rel.go")
        .summary
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .expect("Rel.go reads its path attribute");
    assert!(
        matches!(&read.resource, ResourceExpr::Parameter { name } if name == "self.path"),
        "{read:#?}"
    );
}

#[test]
fn pathlib_mkdir_call_edges_preserve_the_parents_flag() {
    let module = extract(concat!(
        "from resources import tree\n",
        "def create():\n",
        "    tree.mkdir(parents=True)\n",
    ));
    let mkdir = func(&module, "create")
        .calls
        .iter()
        .find(|call| call.callee.ends_with(".mkdir"))
        .expect("mkdir call edge");
    assert!(mkdir.arguments.iter().any(|argument| {
        argument.name.as_deref() == Some("parents")
            && matches!(&argument.value.kind, SemanticValueKind::Literal(value) if value == "true")
    }));
}

#[test]
fn function_parameters_shadow_same_named_module_constants() {
    let module = extract(
        "CONFIG = '/etc/global.conf'\ndef read_config(CONFIG):\n    open(CONFIG)\n    return CONFIG\n",
    );
    let summary = &func(&module, "read_config").summary;
    let read = summary
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .expect("read_config reads its parameter");
    assert!(matches!(
        &read.resource,
        ResourceExpr::Parameter { name } if name == "CONFIG"
    ));
    assert!(matches!(
        summary.returns.as_ref().map(|value| &value.kind),
        Some(SemanticValueKind::Parameter(name)) if name == "CONFIG"
    ));
}

#[test]
fn parameterized_summary_and_local_call_edge() {
    let src = "\
import shutil, os
def wipe(root, t):
    shutil.rmtree(os.path.join(root, t))
def run():
    wipe(BASE, name)
";
    let m = extract(src);

    // wipe's summary carries the parameterized delete on join(root, t).
    let wipe = func(&m, "wipe");
    let delete = wipe
        .summary
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("wipe deletes");
    match &delete.resource {
        ResourceExpr::Join { parts } => {
            assert!(matches!(&parts[0], ResourceExpr::Parameter { name } if name == "root"));
            assert!(matches!(&parts[1], ResourceExpr::Parameter { name } if name == "t"));
        }
        other => panic!("expected join, got {other:?}"),
    }
    assert_eq!(
        wipe.summary.params,
        vec!["root".to_string(), "t".to_string()]
    );

    // run() calls the local wipe: recorded as a call edge with resolved args.
    let run = func(&m, "run");
    let edge = run
        .calls
        .iter()
        .find(|c| c.callee == "wipe")
        .expect("run calls wipe");
    let arguments = edge.resource_arguments();
    assert_eq!(arguments.len(), 2);
    assert!(matches!(&arguments[0], ResourceExpr::Parameter { name } if name == "BASE"));
    assert!(matches!(&arguments[1], ResourceExpr::Parameter { name } if name == "name"));
}

#[test]
fn imported_function_becomes_import_and_edge() {
    let src = "\
from util import wipe
def run(p):
    wipe(p)
";
    let m = extract(src);

    let binding = m
        .imports
        .iter()
        .find(|b| b.local == "wipe")
        .expect("wipe import binding");
    assert_eq!(binding.module, "util");
    assert_eq!(binding.imported.as_deref(), Some("wipe"));

    let run = func(&m, "run");
    assert!(run.calls.iter().any(|c| c.callee == "wipe"));
}

#[test]
fn dotted_module_call_edge_and_binding() {
    let src = "\
import pkg.util as u
def run():
    u.wipe(x)
";
    let m = extract(src);
    let binding = m.imports.iter().find(|b| b.local == "u").unwrap();
    assert_eq!(binding.module, "pkg.util");
    assert_eq!(binding.imported, None);
    // Callee as written is the dotted access.
    assert!(func(&m, "run").calls.iter().any(|c| c.callee == "u.wipe"));
}

#[test]
fn dotted_absolute_import_records_full_callee() {
    let src = "\
import pkg.sub.mod
def run():
    pkg.sub.mod.wipe(x)
";
    let m = extract(src);
    let binding = m.imports.iter().find(|b| b.local == "pkg").unwrap();
    assert_eq!(binding.module, "pkg.sub.mod");
    assert_eq!(binding.imported, None);
    assert!(
        func(&m, "run")
            .calls
            .iter()
            .any(|c| c.callee == "pkg.sub.mod.wipe"),
        "dotted absolute import call is recorded as written: {:?}",
        func(&m, "run").calls
    );
}

#[test]
fn constructor_chained_method_is_an_edge() {
    let src = "\
class App:
    def run(self):
        pass
def main():
    App().run()
";
    let m = extract(src);
    let edge = func(&m, "main")
        .calls
        .iter()
        .find(|c| c.callee == "App.run")
        .expect("App().run() is a call edge");
    assert!(
        matches!(edge.receiver_identity(), Some(ObjectIdentity::Class { name, .. }) if name == "App"),
        "constructor-chained method carries the constructed class: {:?}",
        edge.receiver
    );
}

#[test]
fn self_method_passed_to_registrar_is_a_fn_arg() {
    let src = "\
class App:
    def __init__(self):
        self.add_listener(self.boot)
    def add_listener(self, fn):
        pass
    def boot(self):
        pass
";
    let m = extract(src);
    let init = func(&m, "App.__init__");
    let edge = init
        .calls
        .iter()
        .find(|c| c.callee.contains("add_listener"))
        .expect("add_listener is a call edge");
    assert!(
        edge.callback_arguments()
            .any(|(_, function)| function == "boot"),
        "self.boot is recorded as a fn_arg: {:?}",
        edge.arguments
    );
}

#[test]
fn relative_import_keeps_leading_dots() {
    let m = extract("from .helpers import clean\n");
    let b = m.imports.iter().find(|b| b.local == "clean").unwrap();
    assert_eq!(b.module, ".helpers");
    assert_eq!(b.imported.as_deref(), Some("clean"));
}

#[test]
fn modeled_api_calls_are_not_edges() {
    // os.remove is a modeled effect, not a cross-file edge.
    let src = "\
import os
def f(p):
    os.remove(p)
";
    let m = extract(src);
    let f = func(&m, "f");
    assert!(f.calls.is_empty(), "modeled API must not be a call edge");
    assert!(
        f.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete")
    );
}

#[test]
fn records_local_function_passed_as_callback_arg() {
    let src = "\
import os
def work(p):
    os.remove(p)
def apply(fn, p):
    fn(p)
def run():
    apply(work, path)
    apply(fn=work, p=path)
";
    let m = extract(src);

    // apply's body calls its parameter — recorded so compose can bind it.
    let apply = func(&m, "apply");
    assert!(
        apply.calls.iter().any(|c| c.callee == "fn"),
        "call to parameter fn must be an edge: {:?}",
        apply.calls
    );

    let run = func(&m, "run");
    let positional = run
        .calls
        .iter()
        .find(|c| {
            c.callee == "apply"
                && c.callback_arguments()
                    .any(|(argument, _)| argument.name.is_none())
        })
        .expect("positional apply(work, path)");
    let callbacks: Vec<_> = positional.callback_arguments().collect();
    assert_eq!(callbacks.len(), 1);
    assert_eq!(callbacks[0].0.index, 0);
    assert_eq!(callbacks[0].1, "work");

    let keyword = run
        .calls
        .iter()
        .find(|c| {
            c.callee == "apply"
                && c.callback_arguments()
                    .any(|(argument, _)| argument.name.is_some())
        })
        .expect("keyword apply(fn=work)");
    let callback = keyword.callback_arguments().next().unwrap();
    assert_eq!(callback.0.name.as_deref(), Some("fn"));
    assert_eq!(callback.1, "work");
}

#[test]
fn class_methods_are_summarized() {
    let m = extract(
        "class Loader:\n    def __init__(self, p):\n        self._read(p)\n    def _read(self, p):\n        open(p)\n",
    );
    let names: Vec<_> = m.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"Loader.__init__"));
    assert!(names.contains(&"Loader"));
    assert!(names.contains(&"_read"));
    let init = func(&m, "Loader.__init__");
    assert!(
        init.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read"),
        "__init__ should inline self._read's open()"
    );
}

#[test]
fn main_guard_calls_are_entrypoint_only() {
    let src = "\
from util import setup
def main():
    pass
setup()
if __name__ == \"__main__\":
    main()
";
    let m = extract(src);
    // setup() runs whenever the module is imported; main() only as entrypoint.
    assert!(m.module_calls.iter().any(|c| c.callee == "setup"));
    assert!(
        !m.module_calls.iter().any(|c| c.callee == "main"),
        "main-guard call must not be an import-time call: {:?}",
        m.module_calls
    );
    assert!(m.main_calls.iter().any(|c| c.callee == "main"));

    for guard in ["__name__ == '__main__'", "'__main__' == __name__"] {
        let m = extract(&format!(
            "from util import setup, main\nif {guard}:\n    main()\nelse:\n    setup()\n"
        ));
        assert!(m.module_calls.iter().any(|c| c.callee == "setup"));
        assert!(!m.module_calls.iter().any(|c| c.callee == "main"));
        assert!(m.main_calls.iter().any(|c| c.callee == "main"));
    }
    // Other comparisons cannot be discarded as entrypoint-only code.
    for guard in ["__name__ != '__main__'", "__name__ != '__main__' != other"] {
        let m = extract(&format!(
            "from util import setup\nif {guard}:\n    setup()\n"
        ));
        assert!(m.module_calls.iter().any(|c| c.callee == "setup"));
        assert!(m.main_calls.is_empty());
    }
}

#[test]
fn type_checking_imports_never_execute() {
    let src = "\
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from heavy import Boom
else:
    from light import boom
";
    let m = extract(src);
    assert!(
        !m.imports
            .iter()
            .chain(&m.scoped_imports)
            .any(|b| b.module == "heavy"),
        "a TYPE_CHECKING import must not appear: {:?}",
        m.imports
    );
    // The else arm DOES execute at import time.
    assert!(m.imports.iter().any(|b| b.module == "light"));
}

#[test]
fn function_local_imports_are_scoped_not_eager() {
    let src = "\
import os
def run():
    from lib.fs import wipe
    wipe(\"/x\")
";
    let m = extract(src);
    assert!(
        !m.imports.iter().any(|b| b.local == "wipe"),
        "function-local import must not be an import-time binding: {:?}",
        m.imports
    );
    let b = m
        .scoped_imports
        .iter()
        .find(|b| b.local == "wipe")
        .expect("function-local import is still resolvable");
    assert_eq!(b.module, "lib.fs");
}

#[test]
fn defining_a_function_is_not_a_module_call() {
    // Definitions (functions, classes, methods) do not execute their bodies at
    // import time; only real top-level calls do.
    let src = "\
from util import touch
def nuke():
    touch(\"/defs\")
class K:
    def m(self):
        touch(\"/defs-class\")
touch(\"/real\")
";
    let m = extract(src);
    assert_eq!(
        m.module_calls
            .iter()
            .map(|c| c.callee.as_str())
            .collect::<Vec<_>>(),
        vec!["touch"],
        "only the executed top-level call is a module call"
    );
}

#[test]
fn malformed_source_is_empty_no_panic() {
    let m = extract("def (:::\n  garbage $$$");
    assert!(m.functions.is_empty());
    assert!(m.imports.is_empty());
}

#[test]
fn extraction_is_deterministic() {
    let src = "\
from a import x
import b
def g(p):
    x(p)
    b.h(p)
def f(q):
    g(q)
";
    let a = extract(src);
    let b = extract(src);
    assert_eq!(a, b);
    // Functions are in source order.
    assert_eq!(
        a.functions
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        vec!["g", "f"]
    );
}

#[test]
fn walrus_in_if_test_is_captured() {
    // pipx's emojis.py: the env read lives inside a walrus in an if test.
    let src = "\
import os
def use_emojis():
    if (use_emoji := os.getenv(\"PIPX_USE_EMOJI\")) is not None:
        return True
    return False
";
    let m = extract(src);
    let f = func(&m, "use_emojis");
    assert!(
        f.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "environment.read"
                && matches!(&e.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "PIPX_USE_EMOJI")),
        "walrus-bound env read is captured"
    );
}

#[test]
fn environ_subscript_read_is_captured() {
    // cookiecutter's config.py: os.environ['COOKIECUTTER_CONFIG'].
    let src = "\
import os
def config_file():
    return os.environ['COOKIECUTTER_CONFIG']
";
    let m = extract(src);
    let f = func(&m, "config_file");
    assert!(
        f.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "environment.read"
                && matches!(&e.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "COOKIECUTTER_CONFIG")),
        "environ subscript read is captured"
    );
}

#[test]
fn conditional_module_def_and_import_register() {
    // websockets' version.py: def and import both live under a module-level if.
    let src = "\
released = False
if not released:
    import subprocess
    def get_version(tag):
        return subprocess.run(['git', 'describe'], check=True)
    version = get_version('1.0')
";
    let m = extract(src);
    let f = func(&m, "get_version");
    let exec = f
        .summary
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.exec")
        .expect("summarized subprocess spawn is an effect");
    assert!(format!("{:?}", exec.resource).contains("git"));
    assert!(
        m.module_calls.iter().any(|c| c.callee == "get_version"),
        "the guarded top-level call is a module call"
    );
}

#[test]
fn callback_to_unknown_sink_carries_fn_args() {
    // argparse's set_defaults(func=...): the callee never resolves, but the
    // registered local function must ride the edge.
    let src = "\
def _cmd_install(args):
    pass
def build(sub):
    p = sub.add_parser('install')
    p.set_defaults(func=_cmd_install)
";
    let m = extract(src);
    let build = func(&m, "build");
    let edge = build
        .calls
        .iter()
        .find(|c| {
            c.callback_arguments()
                .any(|(_, function)| function == "_cmd_install")
        })
        .expect("set_defaults edge carries the callback");
    assert!(edge.callee.ends_with("set_defaults"));
    // A non-function argument never becomes an fn_arg.
    assert!(
        !build
            .calls
            .iter()
            .flat_map(|c| c.callback_arguments())
            .any(|(_, function)| function == "sub"),
        "only local functions are callback candidates"
    );
}

#[test]
fn awaited_constructor_records_await_dispatch_edge() {
    // websockets: `await connect(uri)` drives connect.__await__.
    let src = "\
from ws.client import connect
async def run(uri):
    websocket = await connect(uri)
";
    let m = extract(src);
    let run = func(&m, "run");
    let edge = run
        .calls
        .iter()
        .find(|c| c.callee == "connect.__await__")
        .expect("await on a constructed instance records an __await__ edge");
    assert!(edge.receiver.is_some());
    assert!(edge.awaited);
}

#[test]
fn async_calls_record_whether_the_result_is_consumed() {
    let src = "\
async def open_conn():
    pass
async def run():
    open_conn()
    consume(open_conn())
    await consume(open_conn())
";
    let m = extract(src);
    assert!(func(&m, "open_conn").is_async);
    let calls: Vec<_> = func(&m, "run")
        .calls
        .iter()
        .filter(|call| call.callee == "open_conn")
        .collect();
    assert_eq!(calls.len(), 3);
    assert!(!calls[0].awaited, "an uncalled coroutine stays deferred");
    assert!(
        !calls[1].awaited,
        "an unknown consumer does not poll a coroutine"
    );
    assert!(
        !calls[2].awaited,
        "awaiting an outer call does not poll a coroutine passed to it"
    );
}

#[test]
fn conditional_coroutine_bindings_survive_untouched_branches() {
    let module = extract(
        "\
async def read(path):
    pass
async def conditional(flag):
    if flag:
        task = read('/conditional')
    await task
async def guarded():
    try:
        task = read('/guarded')
    except Exception:
        return
    await task
",
    );
    for name in ["conditional", "guarded"] {
        let call = func(&module, name)
            .calls
            .iter()
            .find(|call| call.callee == "read")
            .unwrap_or_else(|| panic!("no read call in {name}"));
        assert!(
            call.awaited,
            "conditional coroutine remains awaited: {call:?}"
        );
    }

    let rebound = extract(
        "\
async def read():
    pass
async def run(flag):
    task = read()
    if flag:
        task = None
    await task
",
    );
    let call = func(&rebound, "run")
        .calls
        .iter()
        .find(|call| call.callee == "read")
        .expect("run calls read");
    assert!(
        !call.awaited,
        "an explicitly rebound coroutine is not awaited"
    );
}

#[test]
fn non_call_deferred_roots_do_not_poll_nested_coroutines() {
    let m = extract(
        "import asyncio\nasync def fetch():\n    pass\ndef consume(value):\n    return value\nasync def run(flag, values):\n    for coroutine in (fetch(), fetch()):\n        pass\n    await (consume(fetch()) if flag else None)\n    await asyncio.gather(*[consume(fetch()) for value in values])\n",
    );
    let calls: Vec<_> = func(&m, "run")
        .calls
        .iter()
        .filter(|call| call.callee == "fetch")
        .collect();
    assert_eq!(calls.len(), 4);
    assert!(
        calls.iter().all(|call| !call.awaited),
        "non-call roots do not poll nested coroutine calls: {calls:?}"
    );
}

#[test]
fn async_pollers_mark_only_the_consumed_call() {
    let src = "\
import asyncio
from asyncio import run_coroutine_threadsafe
async def fetch():
    pass
def run_loop():
    loop = asyncio.new_event_loop()
    loop.run_until_complete(fetch())
    loop.create_task(fetch())
    run_coroutine_threadsafe(fetch(), loop)
async def schedule():
    await asyncio.create_task(fetch())
    await asyncio.ensure_future(fetch())
    task = fetch()
    await task
    tasks = [fetch(), fetch()]
    for task in tasks:
        await task
    batched = [fetch(), fetch()]
    batched += []
    await asyncio.gather(*batched)
    async with asyncio.TaskGroup() as group:
        group.create_task(fetch())
";
    let m = extract(src);
    let calls: Vec<_> = ["run_loop", "schedule"]
        .into_iter()
        .flat_map(|name| func(&m, name).calls.iter())
        .filter(|call| call.callee == "fetch")
        .collect();
    assert_eq!(calls.len(), 11);
    assert!(
        calls.iter().all(|call| call.awaited),
        "standard async pollers consume their exact call: {calls:?}"
    );

    let wrong_receiver = extract(
        "async def fetch():\n    pass\nclass Pool:\n    def run_until_complete(self, future):\n        pass\n    def create_task(self, future):\n        pass\ndef run_coroutine_threadsafe(future, loop):\n    pass\nasync def run():\n    pool = Pool()\n    pool.run_until_complete(fetch())\n    pool.create_task(fetch())\n    run_coroutine_threadsafe(fetch(), pool)\n    tasks = [fetch()]\n    for task in tasks:\n        await consume(task)\n",
    );
    let calls: Vec<_> = func(&wrong_receiver, "run")
        .calls
        .iter()
        .filter(|call| call.callee == "fetch")
        .collect();
    assert_eq!(calls.len(), 4);
    assert!(
        calls.iter().all(|call| !call.awaited),
        "lookalike pollers and unawaited containers do not poll: {calls:?}"
    );

    let rebound_receiver = extract(
        "import asyncio\nasync def fetch():\n    pass\nclass Pool:\n    pass\nasync def run():\n    group = asyncio.TaskGroup()\n    async with Pool() as group:\n        group.create_task(fetch())\n",
    );
    let fetch = func(&rebound_receiver, "run")
        .calls
        .iter()
        .find(|call| call.callee == "fetch")
        .expect("the nested coroutine call remains visible");
    assert!(
        !fetch.awaited,
        "a context binding drops stale TaskGroup identity"
    );
}

#[test]
fn consumed_iterable_executes_nested_local_generators() {
    let m = extract(
        "def lines(path):\n    yield open(path).read()\ndef run(left, right):\n    for a, b in zip(lines(left), lines(right)):\n        pass\n",
    );
    let reads: Vec<_> = func(&m, "run")
        .summary
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.read")
        .collect();
    assert_eq!(reads.len(), 2, "both nested generators execute: {reads:?}");
    assert!(matches!(
        &reads[0].resource,
        ResourceExpr::Parameter { name } if name == "left"
    ));
    assert!(matches!(
        &reads[1].resource,
        ResourceExpr::Parameter { name } if name == "right"
    ));
}

#[test]
fn annotated_assignment_records_constructor_chained_call() {
    // `code: int = App().run()` is executed; the annotation must not drop the
    // constructor-chained edge.
    let src = "\
class App:
    def run(self):
        pass
def main() -> int:
    code: int = App().run()
    return code
";
    let m = extract(src);
    let edge = func(&m, "main")
        .calls
        .iter()
        .find(|c| c.callee == "App.run")
        .expect("annotated App().run() is a call edge");
    assert!(
        matches!(edge.receiver_identity(), Some(ObjectIdentity::Class { name, .. }) if name == "App"),
        "annotated constructor-chained call carries the class: {:?}",
        edge.receiver
    );
}

#[test]
fn event_loop_create_connection_is_network() {
    let src = "\
import asyncio
async def open_conn(factory):
    loop = asyncio.get_running_loop()
    await loop.create_connection(factory)
";
    let m = extract(src);
    let f = func(&m, "open_conn");
    assert!(
        f.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "network.request"),
        "loop.create_connection is a network effect"
    );

    let wrong_receiver = extract(
        "async def open_conn(factory):\n    loop = object()\n    await loop.create_connection(factory)\n",
    );
    assert!(
        func(&wrong_receiver, "open_conn")
            .summary
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "network.request"),
        "the method name alone does not establish an event-loop receiver"
    );
}

#[test]
fn tuple_returned_local_bindings_are_recorded() {
    let m = extract(
        "def factory():\n    parser = object()\n    children = {}\n    return parser, children\n",
    );
    assert_eq!(
        func(&m, "factory").return_bindings,
        vec![Some("parser".to_string()), Some("children".to_string())]
    );
}

#[test]
fn lexical_closure_effects_fold_into_parent_without_exporting_the_closure() {
    let module = extract(
        "import os\ndef outer(root):\n    def wipe(name):\n        os.remove(os.path.join(root, name))\n    wipe('cache')\n",
    );
    assert!(
        func(&module, "outer")
            .summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert!(
        module
            .functions
            .iter()
            .all(|function| function.name != "wipe")
    );
}

#[test]
fn decorated_summary_requires_static_identity_evidence() {
    let identity = extract(
        "import os\ndef identity(fn): return fn\n@identity\ndef wipe(path): os.remove(path)\n",
    );
    assert!(
        func(&identity, "wipe")
            .summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );

    let replacement = extract(
        "import os\ndef suppress(fn): return lambda *args: None\n@suppress\ndef wipe(path): os.remove(path)\n",
    );
    let wipe = func(&replacement, "wipe");
    assert!(!wipe.decorator_gate.is_empty());
    assert!(
        wipe.summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_decorator")
    );
}

#[test]
fn call_preserving_library_decorators_require_exact_identity() {
    let exact = extract(
        "import click\nfrom functools import lru_cache\nfrom mypy_extensions import mypyc_attr\n@click.command()\n@click.option('--path')\n@click.argument('path')\n@click.version_option('1')\n@click.pass_context\ndef main(path): open(path)\n@lru_cache\ndef cached(path): open(path)\n@mypyc_attr(patchable=True)\ndef compiled(path): open(path)\n",
    );
    for name in ["main", "cached", "compiled"] {
        assert!(
            func(&exact, name)
                .summary
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{name} keeps its callable summary"
        );
    }

    let wrong_module =
        extract("import impostor as click\n@click.command()\ndef main(path): open(path)\n");
    assert!(!func(&wrong_module, "main").decorator_gate.is_empty());
    assert!(
        func(&wrong_module, "main")
            .summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_decorator")
    );

    let unresolved_name = extract(
        "from .shim import get_framework\nclick = get_framework()\n@click.command()\ndef main(path): open(path)\n",
    );
    assert!(!func(&unresolved_name, "main").decorator_gate.is_empty());
    assert!(
        func(&unresolved_name, "main")
            .summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_decorator")
    );
}

#[test]
fn cross_file_subprocess_summary_keeps_uncomposed_boundary() {
    let module = extract(
        "import subprocess\ndef push():\n    subprocess.run(['git', 'push', '--force', 'origin', 'main'])\n",
    );
    let summary = &func(&module, "push").summary;
    assert!(
        summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    );
    assert!(
        summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "uncomposed_subprocess")
    );
    assert!(
        !summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.remote_sync")
    );
}

#[test]
fn decorator_shapes_preserve_bodies_only_with_static_proof() {
    use effinterp_engine::DecoratorShape;
    let cases = [
        (
            "def identity(fn): return fn",
            "identity",
            DecoratorShape::Identity,
        ),
        (
            "def identity(fn):\n    def inner(*args, **kwargs):\n        return fn(*args, **kwargs)\n    return inner",
            "identity",
            DecoratorShape::Identity,
        ),
        (
            "def identity(fn):\n    @functools.wraps(fn)\n    def inner(*args, **kwargs):\n        return fn(*args, **kwargs)\n    return inner",
            "identity",
            DecoratorShape::Identity,
        ),
        (
            "def identity(fn):\n    async def inner(*args, **kwargs):\n        return await fn(*args, **kwargs)\n    return inner",
            "identity",
            DecoratorShape::Identity,
        ),
        (
            "def identity(attr):\n    def outer(fn):\n        @functools.wraps(fn)\n        def inner(*args, **kwargs):\n            return fn(*args, **kwargs)\n        return inner\n    return outer",
            "identity(attr='x')",
            DecoratorShape::IdentityFactory,
        ),
        (
            "def identity(fn): return lambda *args: None",
            "identity",
            DecoratorShape::Opaque,
        ),
        (
            "def identity(fn):\n    def inner(*args, **kwargs):\n        os.mkdir('/extra')\n        return fn(*args, **kwargs)\n    return inner",
            "identity",
            DecoratorShape::Opaque,
        ),
        (
            "def identity(fn):\n    os.mkdir('/extra')\n    return fn",
            "identity",
            DecoratorShape::Opaque,
        ),
        (
            "def identity(fn):\n    def inner(*args, **kwargs):\n        return fn(os.mkdir('/extra'))\n    return inner",
            "identity",
            DecoratorShape::Opaque,
        ),
        (
            "def identity(fn):\n    def inner(a, b):\n        return fn(b, a)\n    return inner",
            "identity",
            DecoratorShape::Opaque,
        ),
        (
            "def identity(fn):\n    def inner(a=os.mkdir('/extra')):\n        return fn(a)\n    return inner",
            "identity",
            DecoratorShape::Opaque,
        ),
        (
            "def identity(fn):\n    @functools.wraps(os.mkdir('/extra'))\n    def inner(*args, **kwargs):\n        return fn(*args, **kwargs)\n    return inner",
            "identity",
            DecoratorShape::Opaque,
        ),
    ];
    for (definition, decorator, shape) in cases {
        let source = format!(
            "import os\nimport functools\n{definition}\n@{decorator}\ndef wipe(): os.unlink('/x')\nwipe()\n"
        );
        let module = extract(&source);
        assert_eq!(
            func(&module, "identity").decorator_shape,
            shape,
            "{definition}"
        );
        assert_eq!(
            func(&module, "wipe").decorator_gate.is_empty(),
            shape != DecoratorShape::Opaque,
            "{definition}"
        );
        let plan = effinterp_engine::Engine::new()
            .analyze(&effinterp_proto::Subject::Source {
                dialect: None,
                language: "python".into(),
                source,
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_decorator"),
            shape == DecoratorShape::Opaque,
            "{definition}"
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{definition}"
        );
    }
}

#[test]
fn stdlib_decorators_and_imported_plan_honesty() {
    for decorator in [
        "cache",
        "functools.cache",
        "cached_property",
        "property",
        "x.setter",
        "x.getter",
        "x.deleter",
        "abstractmethod",
        "typing.final",
        "typing.override",
        "typing_extensions.override",
        "functools.lru_cache(maxsize=None)",
        "click.command()",
    ] {
        let source = format!(
            "import os\nimport functools\nimport typing\nimport typing_extensions\nimport click\nfrom functools import cache, cached_property\nfrom abc import abstractmethod\n@{decorator}\ndef wipe(): os.unlink('/x')\n"
        );
        let module = extract(&source);
        let wipe = func(&module, "wipe");
        assert!(wipe.decorator_gate.is_empty(), "{decorator}");
        assert!(
            wipe.summary
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{decorator}"
        );
    }
    for decorator in ["identity", "typing.overload", "registry[0]"] {
        let source = format!(
            "import os\nimport typing\nfrom wrap import identity\n@{decorator}\ndef wipe(): os.unlink('/x')\nwipe()\n"
        );
        let module = extract(&source);
        assert!(!func(&module, "wipe").decorator_gate.is_empty());
        assert!(
            func(&module, "wipe")
                .summary
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
        let plan = effinterp_engine::Engine::new()
            .analyze(&effinterp_proto::Subject::Source {
                dialect: None,
                language: "python".into(),
                source,
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(
                    |boundary| boundary.reason.as_str() == "unresolved_decorator"
                        && boundary.callee.is_some()
                )
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
    }
}

#[test]
fn safe_calls_and_stdlib_resources_survive_summary_capture() {
    let module = extract(
        "from pathlib import Path\nfrom urllib.request import Request, urlopen\nimport os\ndef safe():\n    import sys\n    out = sys.stdout\n    print('x', file=sys.stdout)\n    root = '/srv'\n    os.path.join(root, 'cache')\n    len([1, 2])\n    Path('/input').read_text().strip()\n    req = Request('https://api.github.com/x', data=b'body')\n    urlopen(req)\ndef unsafe(value):\n    str(value)\n    print('x', file=value)\n",
    );
    let safe = &func(&module, "safe").summary;
    assert!(safe.boundaries.is_empty(), "{:?}", safe.boundaries);
    assert!(
        safe.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read")
    );
    assert!(
        safe.effects
            .iter()
            .any(|e| e.operation.0 == "network.upload")
    );
    assert!(safe.effects.iter().all(|e| !e.provenance.is_empty()));
    assert!(!func(&module, "unsafe").summary.boundaries.is_empty());
}

#[test]
fn rebound_values_do_not_quiet_summary_calls() {
    for (body, callee) in [
        ("def run(format):\n    format('x')\nrun(unknown)", "format"),
        ("def run(str=unknown):\n    str('x')\nrun()", "str"),
        ("def run(*, len):\n    len('x')\nrun(len=unknown)", "len"),
        ("def run(*print):\n    print('x')\nrun(unknown)", "print"),
        ("def run(**str):\n    str('x')\nrun(x=unknown)", "str"),
        (
            "import builtins\ndef change():\n    builtins.print = unknown\n[change() for x in [1]]\nprint('x')",
            "print",
        ),
        (
            "import builtins\ndef change():\n    builtins.print = unknown\n[change() for x in items]\nprint('x')",
            "print",
        ),
        ("(len := unknown)\nlen('x')", "len"),
        (
            "import sys\nout, = [sys.stdout]\nalias = out\nalias.write = unknown\nprint('x')",
            "print",
        ),
        (
            "import sys\nout = sys.stdout\nfor out.write in items:\n    pass\nprint('x')",
            "print",
        ),
        ("import foo\nwith foo.cm() as len:\n    len([1])", "len"),
        (
            "import foo\nasync with foo.cm() as len:\n    len([1])",
            "len",
        ),
        (
            "import foo, sys\nwith foo.cm() as sys:\n    print('x', file=sys.stdout)",
            "print",
        ),
        (
            "import foo, json\nwith foo.cm() as json:\n    json.dumps('x')",
            "json.dumps",
        ),
        (
            "import foo, os\nwith foo.cm() as os:\n    os.path.join('a', 'b')",
            "os.path.join",
        ),
        (
            "import sys, foo\nout = sys.stdout\nout.write = foo.w\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nout.__class__ = foo.C\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stderr\nout.__class__ = foo.C\nprint('x', file=sys.stderr)",
            "print",
        ),
        (
            "import sys, foo\ndef h(o):\n    o.__class__ = foo.C\nh(sys.stdout)\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nout.flush = foo.w\nprint('x', flush=True)",
            "print",
        ),
        (
            "import sys, foo\ndef h(o):\n    o.flush = foo.w\nh(sys.stdout)\nprint('x', flush=True)",
            "print",
        ),
        (
            "from sys import stderr\nout, = [stderr]\nout.flush = unknown\nprint('x', file=stderr, flush=True)",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nfor out.__class__ in [foo.C]:\n    pass\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nwith foo.cm() as out.flush:\n    print('x', flush=True)",
            "print",
        ),
        (
            "from sys import stdout\nout = stdout\nout.write = unknown\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nfor sys.stdout in [foo.w]:\n    pass\nprint('x')",
            "print",
        ),
        (
            "import builtins, foo\nfor builtins.len in [foo.f]:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nasync for builtins.len in items:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nwith foo.cm() as builtins.len:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nasync with foo.cm() as builtins.len:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nfor (x, builtins.len) in items:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins\n[0 for builtins.len in items]\nlen([1])",
            "len",
        ),
        (
            "def g():\n    pass\nd = g.__globals__\nd['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "d = (lambda: 0).__globals__\nd['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "def g():\n    pass\ng.__globals__['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "def run():\n    d = run.__globals__\n    d['len'] = unknown\n    len('x')\nrun()",
            "len",
        ),
        (
            "import os\ns = os.__dict__['sys']\ns.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import os\nd = os.__dict__\nd['sys'].stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import os\nos.__dict__['sys'].stdout = writer\nprint('x')",
            "print",
        ),
        (
            "from os import __dict__ as d\nd['sys'].stdout = writer\nprint('x')",
            "print",
        ),
        ("d = frame.f_globals\nd['len'] = unknown\nlen('x')", "len"),
        ("d = frame.f_builtins\nd['len'] = unknown\nlen('x')", "len"),
        (
            "s = 'x'\nd = frame.f_locals\nd['s'] = unknown\nstr(s)",
            "str",
        ),
        (
            "def g():\n    pass\nd = {'ns': g.__globals__}\nd['ns']['len'] = unknown\nlen('x')",
            "len",
        ),
        ("b = print.__self__\nb.len = unknown\nlen('x')", "len"),
        (
            "p = print\nb = p.__self__\nb.len = unknown\nlen('x')",
            "len",
        ),
        ("print.__self__.len = unknown\nlen('x')", "len"),
        (
            "from builtins import print as p\nb = p.__self__\nb.len = unknown\nlen('x')",
            "len",
        ),
        (
            "from os import sys\nsys.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "from os import sys as s\ns.stdout = writer\nprint('x')",
            "print",
        ),
        ("import os\nos.sys.stdout = writer\nprint('x')", "print"),
        (
            "import os\nm = os.sys\nm.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import logging\nlogging.sys.stdout = writer\nprint('x')",
            "print",
        ),
        ("m = unknown.builtins\nm.len = unknown\nlen('x')", "len"),
        (
            "from module import __main__ as m\nm.print = unknown\nprint('x')",
            "print",
        ),
        (
            "import os\ndef run():\n    os.sys.stdout = writer\n    print('x')\nrun()",
            "print",
        ),
        (
            "def run():\n    b = print.__self__\n    b.len = unknown\n    len('x')\nrun()",
            "len",
        ),
        (
            "import builtins\nbuiltins.print = unknown\nprint('x')",
            "print",
        ),
        ("import builtins as b\nb.str = unknown\nstr('x')", "str"),
        ("__builtins__.print = unknown\nprint('x')", "print"),
        (
            "d = __builtins__.__dict__\nd['print'] = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\nx = builtins\nx.print = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\ndef change(m):\n    m.print = unknown\nchange(builtins)\nprint('x')",
            "print",
        ),
        (
            "import builtins\nd = {'b': builtins}\nd['b'].print = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\nfor m in [builtins]:\n    m.print = unknown\nprint('x')",
            "print",
        ),
        (
            "from builtins import __dict__ as d\nd['print'] = unknown\nprint('x')",
            "print",
        ),
        (
            "from builtins import __dict__\n__dict__['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "import sys\nm = sys\nm.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import sys\ndef change(m):\n    m.stdout = writer\nchange(sys)\nprint('x')",
            "print",
        ),
        (
            "import sys\nsys.stdout.write = unknown\nprint('x')",
            "print",
        ),
        (
            "import sys\ns = 'a'\nm = sys.modules[__name__]\nm.s = obj\nstr(s)",
            "str",
        ),
        ("import __main__\ns = 'a'\n__main__.s = obj\nstr(s)", "str"),
        (
            "import builtins\ndef namespace():\n    return builtins\nm = namespace()\nm.print = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\nbuiltins.__dict__['len'] = unknown\nlen('x')",
            "len",
        ),
        ("globals()['print'] = unknown\nprint('x')", "print"),
        ("s = 'a'\nglobals()['s'] = obj\nstr(s)", "str"),
        (
            "import sys\ns = 'a'\nsys.modules[__name__].s = obj\nstr(s)",
            "str",
        ),
        (
            "import sys\nsys.__dict__['stdout'] = writer\nprint('x')",
            "print",
        ),
        (
            "import builtins\ndef change():\n    builtins.print = unknown\nchange()\nprint('x')",
            "print",
        ),
        ("s = 'a'\n_, s = 1, obj\nstr(s)", "str"),
        (
            "p = '/a'\nfor p in items:\n    os.path.join(p, 'x')",
            "join",
        ),
        ("v = [1]\nwhile cond:\n    str(v)\n    v = obj", "str"),
        ("e = 'a'\ntry:\n    pass\nexcept E as e:\n    str(e)", "str"),
        ("s = 'a'\n[str(s) for s in items]", "str"),
        (
            "s = 'a'\ndef change(*args):\n    nonlocal s\n    s = obj\nd = {'k': change}\nd['k']()\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    nonlocal s\n    s = obj\nx = [change]\nx[0]()\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    nonlocal s\n    s = obj\nlist(map(change, [1]))\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    nonlocal s\n    s = obj\nsorted([1], key=change)\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\nclass K:\n    nonlocal s\n    s = obj\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change():\n    nonlocal s\n    s = obj\nclass K:\n    unknown(change)\nstr(s)",
            "str",
        ),
        ("sys.stdout = writer\nprint('x')", "print"),
    ] {
        let body = body
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>();
        let module = extract(&format!("import os, sys\ndef main():\n{body}"));
        let summary = &func(&module, "main").summary;
        assert!(
            summary.boundaries.iter().any(|b| {
                b.callee.as_ref().is_some_and(|c| c.symbol == callee) && !b.provenance.is_empty()
            }),
            "{body}: {:?}",
            summary.boundaries
        );
    }
}

#[test]
fn raise_captures_calls_in_exception_and_cause() {
    let module = extract(
        "from commands import main, cause\ndef launch():\n    raise SystemExit(main()) from cause()\n",
    );
    let launch = func(&module, "launch");
    assert!(launch.calls.iter().any(|call| call.callee == "main"));
    assert!(launch.calls.iter().any(|call| call.callee == "cause"));
}
