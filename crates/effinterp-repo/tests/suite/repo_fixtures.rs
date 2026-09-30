//! Layer-3 repository fixtures: small multi-file repos, each asserting one
//! repository-level condition — attribution, sharing, cycles, aliases, mixed
//! languages, realms, duplicate paths, empty repos, and incremental discovery.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use effinterp_repo::{
    IndexLimits, RepoChange, Selector, apply_changes, build_index, effects_of, reach,
};

use crate::support::antecedent_origins;

static NEXT_TEMP_REPO: AtomicU64 = AtomicU64::new(0);

fn temp_repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let nonce = NEXT_TEMP_REPO.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, content) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}

fn build(root: &Path) -> effinterp_repo::RepoIndex {
    build_index(root, IndexLimits::default())
}

/// Every occurrence a fact's roots derive from, walking the envelope graph
/// backwards the way explanation does.
#[test]
fn composer_bin_reaches_registered_install_command_effects() {
    let root = temp_repo(
        "composer-symfony-commands",
        &[
            (
                "composer.json",
                r#"{"bin":["bin/composer"],"autoload":{"psr-4":{"Composer\\":"src/"}}}"#,
            ),
            (
                "bin/composer",
                "#!/usr/bin/env php\n<?php $application = new Composer\\Console\\Application(); $application->run();\n",
            ),
            (
                "src/Console/Application.php",
                r#"<?php
namespace Composer\Console;
class Application extends \Symfony\Component\Console\Application {
    protected function getDefaultCommands(): array {
        return [new \Composer\Command\InstallCommand(new \Composer\Installer())];
    }
}
"#,
            ),
            (
                "src/Command/InstallCommand.php",
                r#"<?php
namespace Composer\Command;
class InstallCommand {
    private $installer;
    public function __construct(\Composer\Installer $installer) { $this->installer = $installer; }
    protected function execute() { $this->installer->install(); }
}
"#,
            ),
            (
                "src/Installer.php",
                r#"<?php
namespace Composer;
class Installer {
    public function install() {
        file_get_contents('https://repo.packagist.org/packages.json');
        file_put_contents('/project/vendor/composer/installed.php', 'packages');
        system('git clone dependency');
    }
}
"#,
            ),
        ],
    );
    let index = build(&root);
    let composition = index.composition("bin/composer").unwrap();
    let effects = &composition.effects;
    for operation in ["network.request", "filesystem.write", "process.exec"] {
        assert!(effects.iter().any(|effect| {
            effect.effect.operation.0 == operation
                && composition.occurrence_effects.iter().any(|occurrence| {
                    composition.effects[occurrence.effect].effect.id == effect.effect.id
                        && occurrence
                            .via_dispatch
                            .as_ref()
                            .is_some_and(|dispatch| dispatch.model == "symfony-console")
                })
        }));
    }
}

#[test]
fn asdf_urfave_entrypoint_dispatches_nested_actions_by_exact_type() {
    fn fixture(tag: &str, urfave_path: &str) -> PathBuf {
        temp_repo(
            tag,
            &[
                ("go.mod", "module example.com/asdf\n\ngo 1.21\n"),
                (
                    "cmd/asdf/main.go",
                    "package main\nimport \"example.com/asdf/internal/cli\"\nfunc main() { cli.Execute() }\n",
                ),
                (
                    "internal/cli/cli.go",
                    &format!(
                        r#"package cli
import (
    "context"
    "{urfave_path}"
    "example.com/asdf/internal/run"
)
func Execute() {{
    app := &cli.Command{{Commands: []*cli.Command{{
        {{Name: "exec", Action: func(context.Context, *cli.Command) error {{ run.Direct(); return nil }}}},
        {{Name: "shell", Action: func(context.Context, *cli.Command) error {{ run.Shell(); return nil }}}},
    }}}}
    app.Run(context.Background(), nil)
}}
"#,
                    ),
                ),
                (
                    "internal/run/run.go",
                    r#"package run
import (
    "os/exec"
    "syscall"
)
func Direct() { syscall.Exec("/usr/bin/asdf", nil, nil) }
func Shell() { exec.Command("bash", "-c", "echo ok").Run() }
"#,
                ),
            ],
        )
    }

    let positive = build(&fixture("p11b-asdf-urfave", "github.com/urfave/cli/v3"));
    let composition = positive.composition("cmd/asdf/main.go").unwrap();
    let effects = &composition.effects;
    assert!(effects.iter().any(|effect| {
        effect.effect.operation.0 == "process.exec"
            && composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.source_file == "internal/run/run.go"
            })
    }));
    let processes: Vec<_> = effects
        .iter()
        .filter(|effect| effect.effect.operation.0 == "process.exec")
        .collect();
    assert_eq!(processes.len(), 2, "{processes:#?}");

    let negative = build(&fixture(
        "p11b-asdf-wrong-urfave",
        "example.com/urfave/cli/v3",
    ));
    assert!(
        negative
            .composition("cmd/asdf/main.go")
            .unwrap()
            .effects
            .is_empty()
    );
}

#[test]
fn go_interface_factory_and_struct_field_preserve_bounded_candidates() {
    fn fixture(tag: &str, field_value: &str) -> PathBuf {
        temp_repo(
            tag,
            &[
                ("go.mod", "module example.com/yq\n\ngo 1.21\n"),
                (
                    "main.go",
                    r#"package main
import (
    "os"
    "example.com/yq/printer"
)
func main() {
    os.Getenv("CONTROL")
    writer, _ := printer.Configure(true)
    output := printer.New(writer)
    output.Print()
}
"#,
                ),
                (
                    "printer/printer.go",
                    &format!(
                        r#"package printer
import "os"
type Writer interface {{ GetWriter() }}
type multiWriter struct{{}}
func (multiWriter) GetWriter() {{ os.Create("split.yml") }}
type singleWriter struct{{}}
func (singleWriter) GetWriter() {{}}
func NewMulti() Writer {{ return &multiWriter{{}} }}
func NewSingle() Writer {{ return &singleWriter{{}} }}
func Configure(split bool) (Writer, error) {{
    var writer Writer
    if split {{ writer = NewMulti() }} else {{ writer = NewSingle() }}
    return writer, nil
}}
type Printer struct {{ writer Writer }}
func New(writer Writer) *Printer {{ return &Printer{{writer: {field_value}}} }}
func (p *Printer) Print() {{ p.writer.GetWriter() }}
"#,
                    ),
                ),
            ],
        )
    }

    let positive = build(&fixture("p11b-go-interface-field", "writer"));
    assert!(
        positive
            .composition("main.go")
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.effect.operation.0 == "filesystem.write"
                && positive
                    .composition("main.go")
                    .unwrap()
                    .occurrence_effects
                    .iter()
                    .any(
                        |occurrence| positive.composition("main.go").unwrap().effects
                            [occurrence.effect]
                            .effect
                            .id
                            == effect.effect.id
                            && occurrence.source_file == "printer/printer.go"
                    ))
    );

    let negative = build(&fixture("p11b-go-interface-field-negative", "nil"));
    assert!(
        negative
            .composition("main.go")
            .unwrap()
            .effects
            .iter()
            .all(|effect| effect.effect.operation.0 != "filesystem.write")
    );
}

#[test]
fn go_shell_executor_keeps_environment_executable_and_command_shape() {
    let root = temp_repo(
        "go-shell-executor",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/util\"\nfunc main() { executor := util.NewExecutor(); executor.ExecCommand(\"rm -rf /claimed\") }\n",
            ),
            (
                "util/executor.go",
                r#"package util
import (
    "os"
    "os/exec"
)
type Executor struct {
    shell string
    args []string
}
func NewExecutor() *Executor {
    shell := os.Getenv("SHELL")
    if len(shell) == 0 {
        shell = "sh"
    }
    args := []string{"-c"}
    return &Executor{shell, args}
}
func (executor *Executor) ExecCommand(command string) *exec.Cmd {
    return exec.Command(executor.shell, append(executor.args, command)...)
}
"#,
            ),
        ],
    );
    let effects = effects_of(&build(&root), "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let mut processes: Vec<_> = effects
        .effects
        .iter()
        .filter_map(|effect| {
            if effect.operation.as_str() != "process.exec" {
                return None;
            }
            let effinterp_proto::ResourceExpr::Concrete {
                identity:
                    effinterp_proto::ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } = &effect.resource
            else {
                return None;
            };
            Some((executable.as_str(), argv))
        })
        .collect();
    processes.sort_by_key(|(executable, _)| *executable);
    assert_eq!(
        processes
            .iter()
            .map(|(executable, _)| *executable)
            .collect::<Vec<_>>(),
        vec!["$SHELL", "sh"]
    );
    assert!(processes.iter().all(|(_, argv)| matches!(
        argv.as_slice(),
        [
            effinterp_proto::ResourceExpr::Literal { value },
            effinterp_proto::ResourceExpr::Unresolved { family }
        ] if value == "-c" && family.0 == "process_command"
    )));
}

/// The same executor invoked without a name for the constructor's result:
/// `util.NewExecutor().ExecCommand(...)` must dispatch exactly as the two-step
/// form does, and keep the environment-derived executable.
#[test]
fn go_shell_executor_dispatches_on_a_constructor_result() {
    let root = temp_repo(
        "go-chained-shell-executor",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/util\"\nfunc main() { util.NewExecutor().ExecCommand(\"rm -rf /claimed\") }\n",
            ),
            (
                "util/executor.go",
                r#"package util
import (
    "os"
    "os/exec"
)
type Executor struct {
    shell string
    args []string
}
func NewExecutor() *Executor {
    shell := os.Getenv("SHELL")
    if len(shell) == 0 {
        shell = "sh"
    }
    args := []string{"-c"}
    return &Executor{shell, args}
}
func (executor *Executor) ExecCommand(command string) *exec.Cmd {
    return exec.Command(executor.shell, append(executor.args, command)...)
}
"#,
            ),
        ],
    );
    let effects = effects_of(&build(&root), "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let mut executables: Vec<_> = effects
        .effects
        .iter()
        .filter_map(|effect| {
            if effect.operation.as_str() != "process.exec" {
                return None;
            }
            let effinterp_proto::ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::Process { executable, .. },
            } = &effect.resource
            else {
                return None;
            };
            Some(executable.as_str())
        })
        .collect();
    executables.sort_unstable();
    assert_eq!(executables, vec!["$SHELL", "sh"]);
}

#[test]
fn cobra_persistent_hook_requires_the_exact_command_type() {
    fn fixture(tag: &str, cobra_path: &str) -> PathBuf {
        temp_repo(
            tag,
            &[
                ("go.mod", "module example.com/yq\n\ngo 1.21\n"),
                (
                    "main.go",
                    &format!(
                        r#"package main
import (
    "os"
    "{cobra_path}"
)
func main() {{
    root := &cobra.Command{{PersistentPreRunE: func(*cobra.Command, []string) error {{
        os.Getenv("NO_COLOR")
        return nil
    }}}}
    root.Execute()
}}
"#,
                    ),
                ),
            ],
        )
    }

    let positive = build(&fixture("p11b-cobra-persistent", "github.com/spf13/cobra"));
    assert_eq!(reached_by(&positive, "env:NO_COLOR"), vec!["main.go"]);

    let negative = build(&fixture(
        "p11b-cobra-persistent-negative",
        "example.com/spf13/cobra",
    ));
    assert!(reached_by(&negative, "env:NO_COLOR").is_empty());
}

#[test]
fn returned_javascript_cleanup_runs_only_when_the_produced_method_is_passed() {
    fn fixture(tag: &str, callback: &str) -> PathBuf {
        temp_repo(
            tag,
            &[
                (
                    "app.js",
                    "#!/usr/bin/env node\nimport { writeSafe } from './utils.js'\nwriteSafe()\n",
                ),
                (
                    "utils.js",
                    &format!(
                        r#"import {{ promises as fs }} from 'node:fs'
async function openTemp() {{
    return fs.open('tmp', 'w').then(fd => ({{
        cleanup() {{ fd.close().then(() => fs.unlink('tmp')) }},
    }}))
}}
export async function writeSafe() {{
    const temp = await openTemp()
    return fs.writeFile('out', 'x').finally({callback})
}}
"#,
                    ),
                ),
            ],
        )
    }

    let positive = build(&fixture("p11b-js-returned-cleanup", "temp.cleanup"));
    assert!(
        positive
            .composition("app.js")
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect.effect.operation.0 == "filesystem.delete"
                && positive
                    .composition("app.js")
                    .unwrap()
                    .occurrence_effects
                    .iter()
                    .any(|occurrence| positive.composition("app.js").unwrap().effects
                        [occurrence.effect]
                        .effect
                        .id
                        == effect.effect.id
                        && occurrence.source_file == "utils.js"))
    );

    let negative = build(&fixture(
        "p11b-js-returned-cleanup-negative",
        "other.cleanup",
    ));
    assert!(
        negative
            .composition("app.js")
            .unwrap()
            .effects
            .iter()
            .all(|effect| effect.effect.operation.0 != "filesystem.delete")
    );
}

#[test]
fn prettier_literal_import_wrapper_reaches_cli_file_effects() {
    let root = temp_repo(
        "p11b-js-prettier-literal-import",
        &[
            (
                "package.json",
                r#"{"name":"prettier","bin":{"prettier":"bin/prettier.cjs"}}"#,
            ),
            (
                "bin/prettier.cjs",
                r#"#!/usr/bin/env node
function run() {
    var dynamicImport = new Function("module", "return import(module)");
    return dynamicImport("../src/cli/index.js").then(cli => cli.run());
}
module.exports.__promise = run();
"#,
            ),
            (
                "src/cli/index.js",
                "import { readFile, writeFile } from 'node:fs/promises'\n\
                 export async function run() {\n\
                   await readFile('input.js')\n\
                   if (process.env.WRITE_OUTPUT) await writeFile('output.js', '')\n\
                 }\n",
            ),
        ],
    );
    let index = build(&root);
    let report = effects_of(&index, "bin/prettier.cjs")
        .expect("Prettier wrapper analyzed")
        .payload
        .into_effects()
        .unwrap();

    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("input.js")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "src/cli/index.js"
    }));
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.write"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("output.js")
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "src/cli/index.js"
            && effect.modality == effinterp_proto::Modality::May
    }));
}

#[test]
fn python_static_class_tuple_dispatches_exact_imported_constructors() {
    fn fixture(tag: &str, loop_source: &str) -> PathBuf {
        temp_repo(
            tag,
            &[
                (
                    "main.py",
                    "#!/usr/bin/env python\nfrom discover import discover\ndiscover('/tmp/project')\n",
                ),
                (
                    "discover.py",
                    &format!(
                        "from ini_source import IniSource\nfrom toml_source import TomlSource\nSOURCE_TYPES = (IniSource, TomlSource)\ndef discover(path):\n    {loop_source}\n"
                    ),
                ),
                (
                    "ini_source.py",
                    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pathlib import Path\nclass IniSource:\n    def __init__(self, path: Path):\n        path.read_text()\n",
                ),
                (
                    "toml_source.py",
                    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pathlib import Path\nclass TomlSource:\n    def __init__(self, path: Path):\n        path.open('rb')\n",
                ),
            ],
        )
    }

    let positive = build(&fixture(
        "p11b-python-class-tuple",
        "for source_type in SOURCE_TYPES:\n        source_type(path)",
    ));
    let composition = positive.composition("main.py").unwrap();
    let effects = &composition.effects;
    assert!(effects.iter().any(|effect| {
        effect.effect.operation.0 == "filesystem.read"
            && composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.source_file == "ini_source.py"
            })
    }));
    assert!(effects.iter().any(|effect| {
        effect.effect.operation.0 == "filesystem.read"
            && composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.source_file == "toml_source.py"
            })
    }));

    let negative = build(&fixture(
        "p11b-python-class-tuple-negative",
        "for source_type in get_source_types():\n        source_type(path)",
    ));
    assert!(
        negative
            .composition("main.py")
            .is_none_or(|composition| composition.effects.is_empty())
    );
}

#[test]
fn python_super_dispatches_only_the_declared_base() {
    fn fixture(tag: &str, parent_call: &str) -> PathBuf {
        temp_repo(
            tag,
            &[
                (
                    "main.py",
                    "#!/usr/bin/env python\nfrom parser import Child\nChild()\n",
                ),
                (
                    "parser.py",
                    &format!(
                        "from config import Config\nclass Base:\n    def __init__(self):\n        Config()\nclass Child(Base):\n    def __init__(self):\n        {parent_call}.__init__()\n"
                    ),
                ),
                (
                    "config.py",
                    "import os\nclass Config:\n    KEY = 'EXACT_BASE'\n    def __init__(self):\n        os.environ.get(self.KEY)\n",
                ),
            ],
        )
    }

    let positive = build(&fixture("p11b-python-super", "super()"));
    assert_eq!(reached_by(&positive, "env:EXACT_BASE"), vec!["main.py"]);

    let negative = build(&fixture("p11b-python-super-negative", "parent()"));
    assert!(reached_by(&negative, "env:EXACT_BASE").is_empty());
}

/// Entrypoints whose reach matches the selector.
fn reached_by(idx: &effinterp_repo::RepoIndex, selector: &str) -> Vec<String> {
    let mut ids: Vec<String> = reach(idx, &Selector::parse(selector).unwrap(), None)
        .payload
        .into_reach()
        .unwrap()
        .matches
        .into_iter()
        .map(|h| h.fact.entrypoint)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

const UTIL_PY: &str = "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n";

/// An uncalled function's cross-file effect must NOT appear on the
/// entrypoint's FORWARD surface (effects_of), locking in the
/// execution-reachability fix from the reverse-query side's counterpart.
#[test]
fn uncalled_cross_file_function_is_off_the_forward_surface() {
    let root = temp_repo(
        "fix-uncalled",
        &[
            (
                "app.py",
                "from util import wipe\n\ndef never_called():\n    wipe(\"/important\")\n\nif __name__ == \"__main__\":\n    print(\"safe\")\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    let idx = build(&root);
    let fwd = effects_of(&idx, "app.py").expect("app.py analyzed");
    assert!(
        !fwd.payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("important")),
        "uncalled wipe must not be on the execution surface: {:?}",
        fwd.payload.as_effects().unwrap().effects
    );

    // Control: the same repo with a real call attributes the delete.
    let called = temp_repo(
        "fix-called",
        &[
            (
                "app.py",
                "from util import wipe\n\nif __name__ == \"__main__\":\n    wipe(\"/important\")\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    let fwd = effects_of(&build(&called), "app.py").unwrap();
    assert!(
        fwd.payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("important")),
        "the called version must attribute the delete"
    );
}

/// Two entrypoints share one library; each gets only its own specialized
/// effect, not the union of every caller's.
#[test]
fn shared_library_effects_stay_per_entrypoint() {
    let root = temp_repo(
        "fix-shared-lib",
        &[
            (
                "migrate.py",
                "#!/usr/bin/env python\nfrom util import wipe\nwipe(\"/data/migrations\")\n",
            ),
            (
                "cleanup.py",
                "#!/usr/bin/env python\nfrom util import wipe\nwipe(\"/data/cache\")\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    let idx = build(&root);
    assert_eq!(
        reached_by(&idx, "fs:/data/migrations"),
        vec!["migrate.py"],
        "only migrate.py reaches /data/migrations"
    );
    assert_eq!(
        reached_by(&idx, "fs:/data/cache"),
        vec!["cleanup.py"],
        "only cleanup.py reaches /data/cache"
    );
}

/// An import cycle spanning files must terminate and still attribute the
/// effect reached through the cycle.
#[test]
fn import_cycle_terminates_and_attributes() {
    let root = temp_repo(
        "fix-cycle",
        &[
            (
                "a.py",
                "#!/usr/bin/env python\nfrom b import beta\ndef alpha():\n    beta()\nalpha()\n",
            ),
            (
                "b.py",
                "from a import alpha\nimport shutil\ndef beta():\n    shutil.rmtree(\"/cycle/target\")\n    alpha()\n",
            ),
        ],
    );
    // Termination is the primary assertion: build_index must return.
    let idx = build(&root);
    assert_eq!(
        reached_by(&idx, "fs:/cycle/target"),
        vec!["a.py"],
        "the effect inside the cycle is attributed exactly once"
    );
}

/// An aliased import (`from util import wipe as nuke`) resolves to the same
/// cross-file function.
#[test]
fn aliased_import_resolves_cross_file() {
    let root = temp_repo(
        "fix-alias",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom util import wipe as nuke\nnuke(\"/var/cache/app\")\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    let idx = build(&root);
    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| h.fact.entrypoint == "app.py" && h.fact.operation.as_str() == "filesystem.delete")
        .expect("aliased import composes cross-file");
    assert!(
        antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
            .iter()
            .any(|origin| origin.contains("util.py")),
        "provenance crosses into util.py: {:?}",
        report.provenance
    );
}

/// A re-export chain: app imports `wipe` from api.py, which only re-exports it
/// from util.py. The defining file remains the effect origin.
#[test]
fn reexport_chain_resolves_to_definition() {
    let root = temp_repo(
        "fix-reexport",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom api import wipe\nwipe(\"/srv/data\")\n",
            ),
            ("api.py", "from util import wipe\n"),
            ("util.py", UTIL_PY),
        ],
    );
    let idx = build(&root);
    let report = reach(&idx, &Selector::parse("fs:/srv/data").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "app.py"
                    && hit.fact.operation.as_str() == "filesystem.delete"
                    && hit
                        .fact
                        .origin
                        .as_ref()
                        .is_some_and(|origin| origin.source_file == "util.py")
            }),
        "a re-exported call resolves to its producer: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

/// A package script launches a shell entrypoint which runs a Python script.
/// The launch edges carry the concrete effect onto the package surface.
#[test]
fn mixed_language_subprocess_composes_local_source() {
    let root = temp_repo(
        "fix-mixed-lang",
        &[
            ("package.json", r#"{"scripts":{"run":"./run.sh"}}"#),
            ("run.sh", "#!/bin/sh\npython3 tools/wipe.py\n"),
            (
                "tools/wipe.py",
                "#!/usr/bin/env python\nimport shutil\nshutil.rmtree(\"/opt/app/data\")\n",
            ),
        ],
    );
    let idx = build(&root);
    let report = reach(&idx, &Selector::parse("fs:/opt/app/data").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "package.json:scripts.run"
                && hit.fact.operation.as_str() == "filesystem.delete"
                && hit
                    .fact
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.source_file == "tools/wipe.py")),
        "the package script composes the launched Python source: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    // The script itself is discovered, so the delete is still on the surface.
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "tools/wipe.py"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "the python script's own entrypoint carries the delete: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

/// A shell entrypoint reaches a database table through a container: the effect
/// is realm-scoped to the container and the table stays globally queryable.
#[test]
fn container_to_database_effect() {
    let root = temp_repo(
        "fix-container-db",
        &[(
            "maint.sh",
            "#!/bin/sh\ndocker exec pg psql -c 'DROP TABLE public.orders'\n",
        )],
    );
    let idx = build(&root);
    // The table identity is global: an unqualified db query spans realms.
    assert_eq!(reached_by(&idx, "db:public.orders"), vec!["maint.sh"]);
    // But the execution origin is the container, not the host.
    assert!(reached_by(&idx, "host/db:public.orders").is_empty());

    let fwd = effects_of(&idx, "maint.sh").unwrap();
    let drop = fwd
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::DatabaseTable {
                        schema: Some(schema),
                        table,
                        ..
                    }
                } if schema == "public" && table == "orders"
            )
        })
        .expect("the DROP is on the forward surface");
    assert!(drop.operation.is_destructive(), "DROP TABLE is destructive");
    assert!(
        matches!(
            &drop.realm,
            effinterp_proto::ExecutionRealm::Container { name, .. } if name.contains("pg")
        ),
        "the effect is scoped to the pg container realm: {:?}",
        drop.realm
    );
}

/// A pod-to-cloud effect: `kubectl exec` nests an `aws s3 rm`, producing an
/// object-store delete scoped to the pod realm but globally queryable.
#[test]
fn pod_to_cloud_effect() {
    let root = temp_repo(
        "fix-pod-cloud",
        &[(
            "deploy.sh",
            "#!/bin/sh\nkubectl exec worker -- aws s3 rm s3://backups/nightly.tar\n",
        )],
    );
    let idx = build(&root);
    // Object-store identity is global: unqualified query finds it.
    assert_eq!(
        reached_by(&idx, "obj:backups/nightly.tar"),
        vec!["deploy.sh"]
    );
    // Realm-qualified: the pod realm matches, the host realm does not.
    assert_eq!(
        reached_by(&idx, "pod:worker/obj:backups/nightly.tar"),
        vec!["deploy.sh"]
    );
    assert!(reached_by(&idx, "host/obj:backups/nightly.tar").is_empty());
}

/// The same effect reached through two independent call paths must collapse to
/// one explainable row, not a spurious duplicate.
#[test]
fn duplicate_effect_via_two_paths_is_one_row() {
    let root = temp_repo(
        "fix-two-paths",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom util import wipe\ndef path_a():\n    wipe(\"/shared/state\")\ndef path_b():\n    wipe(\"/shared/state\")\npath_a()\npath_b()\n",
            ),
            ("util.py", UTIL_PY),
        ],
    );
    let idx = build(&root);
    let fwd = effects_of(&idx, "app.py").unwrap();
    let rows: Vec<_> = fwd
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|e| {
            e.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("/shared/state")
        })
        .collect();
    assert_eq!(rows.len(), 1, "one row, not one per path: {rows:?}");
    assert!(!rows[0].provenance_roots.is_empty());

    let report = reach(&idx, &Selector::parse("fs:/shared/state").unwrap(), None);
    let hits: Vec<_> = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .filter(|h| {
            h.fact.entrypoint == "app.py" && h.fact.operation.as_str() == "filesystem.delete"
        })
        .collect();
    assert_eq!(hits.len(), 1, "reach agrees: one hit, not two");
}

/// A repository with no discoverable entrypoints: no panic, empty results.
#[test]
fn repo_without_entrypoints_yields_empty_results() {
    let root = temp_repo(
        "fix-no-entry",
        &[
            ("lib.py", "def helper():\n    return 1\n"),
            ("notes.txt", "no runnable code here\n"),
        ],
    );
    let idx = build(&root);
    assert!(idx.entrypoints.is_empty(), "nothing to discover");
    let report = reach(&idx, &Selector::parse("fs:/anything").unwrap(), None);
    assert!(report.payload.as_reach().unwrap().matches.is_empty());
    assert!(report.payload.as_reach().unwrap().indeterminate.is_empty());
    assert!(effects_of(&idx, "lib.py").is_none());
}

/// An incremental change that affects DISCOVERY: a library file gains a
/// `__main__` guard and becomes an entrypoint. The updated index must match a
/// clean rebuild and expose the new entrypoint's effect.
#[test]
fn incremental_change_affecting_discovery() {
    let root = temp_repo(
        "fix-incremental-disco",
        &[(
            "tool.py",
            "import shutil\ndef clean():\n    shutil.rmtree(\"/tmp/scratch\")\n",
        )],
    );
    let mut idx = build(&root);
    assert!(
        idx.entrypoints.is_empty(),
        "a pure library is not discovered"
    );

    std::fs::write(
        root.join("tool.py"),
        "import shutil\ndef clean():\n    shutil.rmtree(\"/tmp/scratch\")\nif __name__ == \"__main__\":\n    clean()\n",
    )
    .unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("tool.py".into())],
    );

    let rebuilt = build(&root);
    assert_eq!(
        idx.fingerprint, rebuilt.fingerprint,
        "incremental discovery change matches a clean rebuild"
    );
    assert_eq!(
        reached_by(&idx, "fs:/tmp/scratch"),
        vec!["tool.py"],
        "the newly discovered entrypoint's delete is queryable"
    );
}

fn p13e_delete_resources(index: &effinterp_repo::RepoIndex, entrypoint: &str) -> Vec<String> {
    let mut resources: Vec<_> = effects_of(index, entrypoint)
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects
        .into_iter()
        .filter(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/p13e/")
        })
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    resources.sort();
    resources
}

#[test]
fn paired_wrong_receivers_remove_only_the_unsupported_path() {
    let python = |tag: &str, receiver: &str| {
        temp_repo(
            tag,
            &[
                (
                    "app.py",
                    &format!(
                        "#!/usr/bin/env python3\nimport os\nfrom helper import Right, Wrong\nos.remove('/p13e/python-baseline')\n{receiver}().erase()\n"
                    ),
                ),
                (
                    "helper.py",
                    "import os\nclass Right:\n    def erase(self): os.remove('/p13e/python-target')\nclass Wrong: pass\n",
                ),
            ],
        )
    };
    let python_positive = build(&python("p13e-python-positive", "Right"));
    let python_negative = build(&python("p13e-python-negative", "Wrong"));
    assert_eq!(
        p13e_delete_resources(&python_positive, "app.py"),
        ["fs:/p13e/python-baseline", "fs:/p13e/python-target"]
    );
    assert_eq!(
        p13e_delete_resources(&python_negative, "app.py"),
        ["fs:/p13e/python-baseline"]
    );

    let javascript = |tag: &str, receiver: &str| {
        temp_repo(
            tag,
            &[
                (
                    "app.js",
                    &format!(
                        "#!/usr/bin/env node\nimport fs from 'node:fs'\nimport {{ Right, Wrong }} from './helper.js'\nfs.unlinkSync('/p13e/javascript-baseline')\nconst value = new {receiver}()\nvalue.erase()\n"
                    ),
                ),
                (
                    "helper.js",
                    "import fs from 'node:fs'\nexport class Right { erase() { fs.unlinkSync('/p13e/javascript-target') } }\nexport class Wrong {}\n",
                ),
            ],
        )
    };
    let javascript_positive = build(&javascript("p13e-javascript-positive", "Right"));
    let javascript_negative = build(&javascript("p13e-javascript-negative", "Wrong"));
    assert_eq!(
        p13e_delete_resources(&javascript_positive, "app.js"),
        ["fs:/p13e/javascript-baseline", "fs:/p13e/javascript-target"]
    );
    assert_eq!(
        p13e_delete_resources(&javascript_negative, "app.js"),
        ["fs:/p13e/javascript-baseline"]
    );
}

#[test]
fn bat_shaped_pager_pipeline_keeps_the_default_process_source_backed() {
    let root = temp_repo(
        "rust-bat-pager-pipeline",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"bat-pager-fixture\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/main.rs",
                "mod output;\nmod pager;\nfn main() { output::run(); }\n",
            ),
            (
                "src/pager.rs",
                r#"
#[derive(PartialEq)]
pub enum PagerSource { Config, Env, Default }
pub struct Pager { pub bin: String, pub args: Vec<String>, pub source: PagerSource }
impl Pager {
    fn new(bin: &str, args: &[String], source: PagerSource) -> Pager {
        Pager { bin: String::from(bin), args: args.to_vec(), source }
    }
}
pub fn get_pager(config: Option<&str>) -> Result<Option<Pager>, ()> {
    let from_env = std::env::var("PAGER");
    let (cmd, source) = match (config, &from_env) {
        (Some(config), _) => (config, PagerSource::Config),
        (_, Ok(value)) => (value.as_str(), PagerSource::Env),
        _ => ("less", PagerSource::Default),
    };
    let parts = shell_words::split(cmd)?;
    match parts.split_first() {
        Some((bin, args)) => Ok(Some(Pager::new(bin, args, source))),
        None => Ok(None),
    }
}
"#,
            ),
            (
                "src/output.rs",
                r#"
use crate::pager::get_pager;
use std::process::Command;
pub fn run() {
    let pager = match get_pager(None).unwrap() {
        Some(pager) => pager,
        None => return,
    };
    let resolved = match grep_cli::resolve_binary(&pager.bin) {
        Ok(path) => path,
        Err(_) => return,
    };
    let mut command = Command::new(resolved);
    if pager.args.is_empty() {
        command.arg("-R");
    } else {
        command.args(pager.args);
    }
    command.status();
}
"#,
            ),
        ],
    );
    let index = build(&root);
    let composition = index.composition("src/main.rs").unwrap();
    assert!(
        composition.effects.iter().any(|effect| {
            composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.source_file == "src/output.rs"
            }) && matches!(&effect.effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "less")
        }),
        "effects: {:?}",
        composition.effects
    );
}
