#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use effinterp_engine::Assurance;
use effinterp_proto::display_resource_with_scope;
use effinterp_repo::{IndexLimits, build_index};

static NEXT_TEMP_REPO: AtomicU64 = AtomicU64::new(0);

fn temp_repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let nonce = NEXT_TEMP_REPO.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (relative, content) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}

fn resources(index: &effinterp_repo::RepoIndex, entrypoint: &str) -> Vec<String> {
    let mut resources: Vec<_> = index
        .composition(entrypoint)
        .map(|composition| {
            composition
                .effects
                .iter()
                .map(|effect| display_resource_with_scope(&effect.effect.resource))
                .collect()
        })
        .unwrap_or_default();
    resources.sort();
    resources
}

#[test]
fn symfony_keeps_exact_commands_when_a_plugin_is_unresolved() {
    let root = temp_repo(
        "php-symfony-unresolved-plugin",
        &[
            (
                "composer.json",
                r#"{"bin":["bin/tool"],"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "bin/tool",
                "#!/usr/bin/env php\n<?php $app = new App\\Application(); $app->run();\n",
            ),
            (
                "src/Application.php",
                r#"<?php
namespace App;
use Vendor\PluginCommand;
class Application extends \Symfony\Component\Console\Application {
    protected function getDefaultCommands(): array {
        return [new Command(), new PluginCommand()];
    }
}
"#,
            ),
            (
                "src/Command.php",
                "<?php namespace App; class Command { protected function execute() { unlink('/exact-command'); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "bin/tool"), ["fs:/exact-command"]);
    let composition = index.composition("bin/tool").unwrap();
    assert!(
        composition
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "lifecycle_unbound"),
        "{composition:#?}"
    );
    assert_eq!(
        composition.occurrence_effects[0]
            .via_dispatch
            .as_ref()
            .map(|dispatch| dispatch.model.as_str()),
        Some("symfony-console")
    );
}

#[test]
fn cobra_dispatch_is_scoped_to_one_command_tree() {
    let root = temp_repo(
        "p3-cobra-two-trees",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{RunE: runRoot}
var otherCmd = &cobra.Command{RunE: runOther}
func runRoot(cmd *cobra.Command, args []string) error { return os.RemoveAll("/root-fired") }
func runOther(cmd *cobra.Command, args []string) error { return os.RemoveAll("/other-inert") }
func main() { rootCmd.Execute() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "main.go"), vec!["fs:/root-fired"]);
    let effect = &index.composition("main.go").unwrap().occurrence_effects[0];
    assert_eq!(effect.assurance, Assurance::Exact);
    let via = effect.via_dispatch.as_ref().unwrap();
    assert_eq!(via.model, "cobra");
    assert!(!via.registration_path.is_empty());
    assert!(!via.dispatch_path.is_empty());
}

#[test]
fn repository_factories_preserve_returned_dispatcher_identity() {
    let go = temp_repo(
        "p3-go-returned-dispatcher",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
func New() *cobra.Command {
    root := &cobra.Command{RunE: run}
    return root
}
func run(cmd *cobra.Command, args []string) error { return os.RemoveAll("/factory-go") }
func main() { root := New(); root.Execute() }
"#,
            ),
        ],
    );
    assert_eq!(
        resources(&build_index(&go, IndexLimits::default()), "main.go"),
        vec!["fs:/factory-go"]
    );

    let python = temp_repo(
        "p3-python-returned-dispatcher",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
import argparse
import os
def command(): os.remove("/factory-python")
def make():
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=command)
    return parser
parser = make()
parser.parse_args()
"#,
        )],
    );
    assert_eq!(
        resources(&build_index(&python, IndexLimits::default()), "app.py"),
        vec!["fs:/factory-python"]
    );
}

#[test]
fn argparse_dispatch_is_scoped_to_one_parser() {
    let root = temp_repo(
        "p3-argparse-two-trees",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
import argparse
import os
one = argparse.ArgumentParser()
two = argparse.ArgumentParser()
def one_cmd(): os.remove("/one-fired")
def two_cmd(): os.remove("/two-inert")
one.set_defaults(func=one_cmd)
two.set_defaults(func=two_cmd)
one.parse_args()
"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "app.py"), vec!["fs:/one-fired"]);
    let effect = &index.composition("app.py").unwrap().occurrence_effects[0];
    assert_eq!(effect.assurance, Assurance::Heuristic);
    assert_eq!(effect.via_dispatch.as_ref().unwrap().model, "argparse");
}

#[test]
fn same_named_repo_methods_are_not_a_framework_model() {
    let root = temp_repo(
        "p3-generic-two-trees",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
import os
class App:
    def add_command(self, command): pass
    def run(self): pass
class One:
    def run(self): os.remove("/one-fired")
class Two:
    def run(self): os.remove("/two-inert")
one = App()
two = App()
one.add_command(One())
two.add_command(Two())
one.run()
"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(resources(&index, "app.py").is_empty());
}

#[test]
fn cobra_execute_arity_and_untyped_run_do_not_dispatch() {
    let root = temp_repo(
        "p3-lifecycle-near-misses",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{RunE: runRoot}
func runRoot(cmd *cobra.Command, args []string) error { return os.RemoveAll("/never") }
func run() {}
func main() { rootCmd.Execute(nil, nil); run() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(resources(&index, "main.go").is_empty());
}

#[test]
fn cobra_package_roots_join_sibling_initialization_by_origin() {
    let root = temp_repo(
        "p3-cobra-sibling-init",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "root.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{}
var childCmd = &cobra.Command{RunE: childRun}
func childRun(cmd *cobra.Command, args []string) error { return os.RemoveAll("/sibling-child") }
"#,
            ),
            (
                "init.go",
                "package main\nfunc init() { rootCmd.AddCommand(childCmd) }\n",
            ),
            (
                "main.go",
                "package main\nfunc main() { rootCmd.Execute() }\n",
            ),
        ],
    );
    // An unrelated oversized callable must not consume the roots' walk budgets.
    let oversized = format!(
        "package main\nfunc aaa() {{\n{}}}\nfunc init() {{ rootCmd.AddCommand(childCmd) }}\n",
        "_ = 1\n".repeat(400)
    );
    std::fs::write(root.join("init.go"), oversized).unwrap();
    let mut limits = IndexLimits::default();
    *limits.engine.get_mut("max_go_nodes").unwrap() = 128;
    let index = build_index(&root, limits.clone());
    assert_eq!(resources(&index, "main.go"), vec!["fs:/sibling-child"]);
    let composition = index.composition("main.go").unwrap();
    assert_eq!(composition.occurrence_effects[0].source_file, "root.go");
    assert_eq!(
        composition.occurrence_effects[0]
            .via_dispatch
            .as_ref()
            .unwrap()
            .model,
        "cobra"
    );
    assert!(
        composition
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "escaped_callable")
    );
    let via = index.composition("main.go").unwrap().occurrence_effects[0]
        .via_dispatch
        .as_ref()
        .unwrap();
    assert!(
        via.dispatch_path
            .iter()
            .any(|step| step.starts_with("attach:"))
    );
    assert!(
        index
            .composition("main.go")
            .unwrap()
            .boundaries
            .iter()
            .all(|b| b.limit.as_deref() != Some("max_go_nodes"))
    );

    std::fs::write(
        root.join("main.go"),
        "package main\nfunc main() { aaa(); rootCmd.Execute() }\n",
    )
    .unwrap();
    let partial = build_index(&root, limits.clone());
    assert_eq!(resources(&partial, "main.go"), vec!["fs:/sibling-child"]);
    assert!(matches!(
        partial.snapshot_state,
        effinterp_proto::AnalysisStatus::Partial { .. }
    ));
    assert!(
        partial
            .composition("main.go")
            .unwrap()
            .boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_go_nodes"))
    );

    std::fs::write(
        root.join("root.go"),
        r#"package main
import (
    "github.com/spf13/cobra"
    "example.com/eventkit"
    "os"
)
var rootCmd = &cobra.Command{}
var childCmd = &cobra.Command{RunE: childRun}
func wipe() { os.RemoveAll("/unknown-callback") }
func childRun(cmd *cobra.Command, args []string) error {
    eventkit.Register(wipe)
    return os.RemoveAll("/sibling-child")
}
"#,
    )
    .unwrap();
    let unresolved = build_index(&root, limits);
    assert!(
        unresolved
            .composition("main.go")
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "escaped_callable"
                && boundary
                    .via_dispatch
                    .as_ref()
                    .is_some_and(|via| via.model == "cobra"))
    );
}

#[test]
fn cobra_constructor_resolves_package_visible_callback() {
    let root = temp_repo(
        "p3-cobra-sibling-callback",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "root.go",
                r#"package main
import "github.com/spf13/cobra"
var rootCmd = &cobra.Command{RunE: siblingRun}
"#,
            ),
            (
                "callback.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
func siblingRun(cmd *cobra.Command, args []string) error { return os.RemoveAll("/sibling-callback") }
"#,
            ),
            (
                "main.go",
                "package main\nfunc main() { rootCmd.Execute() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "main.go"), vec!["fs:/sibling-callback"]);
    let effect = &index.composition("main.go").unwrap().occurrence_effects[0];
    assert_eq!(effect.source_file, "callback.go");
    assert_eq!(effect.assurance, Assurance::Exact);
    assert_eq!(effect.via_dispatch.as_ref().unwrap().model, "cobra");
}

#[test]
fn go_package_names_and_external_construction_sites_remain_distinct() {
    let root = temp_repo(
        "p3-go-origin-distinction",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport (\n  \"example.com/app/one\"\n  \"example.com/app/two\"\n)\nfunc main() { one.Dispatch(); two.Build() }\n",
            ),
            (
                "one/cmd.go",
                r#"package one
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{RunE: run}
func run(cmd *cobra.Command, args []string) error { return os.RemoveAll("/one-package") }
func Dispatch() { rootCmd.Execute() }
"#,
            ),
            (
                "two/cmd.go",
                r#"package two
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{RunE: run}
func run(cmd *cobra.Command, args []string) error { return os.RemoveAll("/two-package") }
func Build() {}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "main.go"), vec!["fs:/one-package"]);

    let sites = temp_repo(
        "p3-external-sites",
        &[
            ("go.mod", "module example.com/sites\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
func one(cmd *cobra.Command, args []string) error { return os.RemoveAll("/first-site") }
func two(cmd *cobra.Command, args []string) error { return os.RemoveAll("/second-site") }
func main() {
    first := &cobra.Command{RunE: one}
    second := &cobra.Command{RunE: two}
    first.Execute()
    _ = second
}
"#,
            ),
        ],
    );
    let index = build_index(&sites, IndexLimits::default());
    assert_eq!(resources(&index, "main.go"), vec!["fs:/first-site"]);
}

#[test]
fn conditional_attachment_preserves_may_modality() {
    let root = temp_repo(
        "p3-conditional-attachment",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{}
var childCmd = &cobra.Command{RunE: child}
func child(cmd *cobra.Command, args []string) error { return os.RemoveAll("/conditional") }
func main() {
    if true { rootCmd.AddCommand(childCmd) }
    rootCmd.Execute()
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effect = &index.composition("main.go").unwrap().effects[0];
    assert_eq!(
        display_resource_with_scope(&effect.effect.resource),
        "fs:/conditional"
    );
    assert_eq!(effect.effect.modality, effinterp_proto::Modality::May);
}

#[test]
fn python_import_registration_and_alias_dispatch_share_defining_origin() {
    let root = temp_repo(
        "p3-python-import-alias",
        &[
            (
                "commands.py",
                r#"import argparse
import os
parser = argparse.ArgumentParser()
def command(): os.remove("/import-fired")
parser.set_defaults(func=command)
"#,
            ),
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom commands import parser as cli\ncli.parse_args()\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "app.py"), vec!["fs:/import-fired"]);
    assert_eq!(
        index.composition("app.py").unwrap().occurrence_effects[0]
            .via_dispatch
            .as_ref()
            .unwrap()
            .model,
        "argparse"
    );
}

#[test]
fn one_of_two_derived_parsers_dispatches_and_order_is_irrelevant() {
    let root = temp_repo(
        "p3-derived-parser-order",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
import argparse
import os
root = argparse.ArgumentParser()
subs = root.add_subparsers()
one = subs.add_parser("one")
two = subs.add_parser("two")
def first(): os.remove("/first-parser")
def second(): os.remove("/second-parser")
one.parse_args()
one.set_defaults(func=first)
two.set_defaults(func=second)
"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "app.py"), vec!["fs:/first-parser"]);
}

#[test]
fn activated_callback_can_create_round_two_dispatch() {
    let root = temp_repo(
        "p3-dispatch-round-two",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{RunE: first}
func first(cmd *cobra.Command, args []string) error {
    next := &cobra.Command{RunE: second}
    next.Execute()
    return nil
}
func second(cmd *cobra.Command, args []string) error { return os.RemoveAll("/round-two") }
func main() { rootCmd.Execute() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "main.go"), vec!["fs:/round-two"]);
}

#[test]
fn same_callback_on_two_dispatchers_activates_only_the_fired_identity() {
    let root = temp_repo(
        "p3-same-callback-two-dispatchers",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
func shared(cmd *cobra.Command, args []string) error { return os.RemoveAll("/shared") }
func main() {
    one := &cobra.Command{RunE: shared}
    two := &cobra.Command{RunE: shared}
    one.Execute()
    _ = two
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert_eq!(resources(&index, "main.go"), vec!["fs:/shared"]);
    assert_eq!(composition.effects.len(), 1);
}

#[test]
fn dispatch_round_limit_reports_only_a_fired_pending_chain() {
    let root = temp_repo(
        "p3-dispatch-round-limit",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/spf13/cobra"
    "os"
)
var rootCmd = &cobra.Command{RunE: one}
func one(cmd *cobra.Command, args []string) error { next := &cobra.Command{RunE: two}; next.Execute(); return nil }
func two(cmd *cobra.Command, args []string) error { next := &cobra.Command{RunE: three}; next.Execute(); return nil }
func three(cmd *cobra.Command, args []string) error { next := &cobra.Command{RunE: four}; next.Execute(); return nil }
func four(cmd *cobra.Command, args []string) error { next := &cobra.Command{RunE: five}; next.Execute(); return nil }
func five(cmd *cobra.Command, args []string) error { return os.RemoveAll("/past-limit") }
func main() { rootCmd.Execute() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(resources(&index, "main.go").is_empty());
    let exhausted: Vec<_> = composition
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason == "dispatch_rounds_exhausted")
        .collect();
    assert_eq!(exhausted.len(), 1);
    assert!(exhausted[0].detail.contains("five"));
    assert!(exhausted[0].via_dispatch.is_some());
}

#[test]
fn an_untyped_run_does_not_fire_a_registered_tree() {
    let root = temp_repo(
        "p3-untyped-run-inert-tree",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
import os
class App:
    def add_command(self, command): pass
class Command:
    def run(self): os.remove("/must-stay-inert")
def run(): pass
app = App()
app.add_command(Command())
run()
"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(resources(&index, "app.py").is_empty());
    assert!(
        index
            .composition("app.py")
            .into_iter()
            .flat_map(|composition| &composition.boundaries)
            .all(|boundary| boundary.reason != "dispatch_rounds_exhausted")
    );
}

#[test]
fn missing_typed_lifecycle_object_origin_emits_one_boundary() {
    let root = temp_repo(
        "p3-lifecycle-unbound-object",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import "github.com/spf13/cobra"
var rootCmd = &cobra.Command{}
func main() { rootCmd.AddCommand(nil) }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(composition.effects.is_empty());
    let unbound: Vec<_> = composition
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason == "lifecycle_unbound")
        .collect();
    assert_eq!(unbound.len(), 1);
    assert!(unbound[0].detail.contains("object argument 0"));
}

#[test]
fn kong_nested_tagged_commands_dispatch_with_exact_metadata() {
    let root = temp_repo(
        "kong-nested-tagged-commands",
        &[
            ("go.mod", "module example.com/gum\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/alecthomas/kong"
    "example.com/gum/command"
)
type Gum struct {
    Top command.Top `cmd:""`
    Helper command.Helper
    Dynamic command.Runner `cmd:""`
    Missing MissingCommand `cmd:""`
}
func main() {
    gum := &Gum{}
    ctx := kong.Parse(gum)
    ctx.Run()
}
"#,
            ),
            (
                "command/command.go",
                r#"package command
import (
    "os"
    "os/exec"
)
type Top struct {
    Leaf Leaf `cmd:""`
    Plain Plain
}
func (Top) Run() error { return os.RemoveAll("/tagged-top") }
type Leaf struct{}
func (Leaf) Run() error {
    _, _ = os.ReadFile("/tagged-leaf")
    return exec.Command("tagged-tool").Run()
}
type Plain struct{}
func (Plain) Run() error { return os.RemoveAll("/untagged-nested") }
type Helper struct{}
func (Helper) Run() error { return os.RemoveAll("/untagged-root") }
type Runner interface { Run() error }
type Guess struct{}
func (Guess) Run() error { return os.RemoveAll("/interface-guess") }
func Spare() error { return os.RemoveAll("/spare") }
"#,
            ),
        ],
    );
    let built = build_index(&root, IndexLimits::default());
    let composition = built.composition("main.go").unwrap();
    let mut resources: Vec<_> = composition
        .effects
        .iter()
        .map(|effect| display_resource_with_scope(&effect.effect.resource))
        .collect();
    resources.sort();
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("/tagged-top"))
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("/tagged-leaf"))
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("tagged-tool"))
    );
    for absent in [
        "/untagged-nested",
        "/untagged-root",
        "/interface-guess",
        "/spare",
    ] {
        assert!(resources.iter().all(|resource| !resource.contains(absent)));
    }
    assert!(composition.occurrence_effects.iter().all(|effect| {
        effect.assurance == Assurance::Exact
            && composition.effects[effect.effect].effect.modality == effinterp_proto::Modality::May
            && effect
                .via_dispatch
                .as_ref()
                .is_some_and(|dispatch| dispatch.model == "kong")
    }));
    let registration_paths: Vec<_> = composition
        .occurrence_effects
        .iter()
        .map(|effect| {
            effect
                .via_dispatch
                .as_ref()
                .unwrap()
                .registration_path
                .clone()
        })
        .collect();
    assert!(registration_paths.iter().any(|path| {
        path.iter().any(|step| step == "field:main.go:Gum.Top")
            && path
                .iter()
                .any(|step| step == "field:command/command.go:Top.Leaf")
    }));
    assert!(composition.occurrence_effects.iter().all(|effect| {
        !effect
            .via_dispatch
            .as_ref()
            .unwrap()
            .dispatch_path
            .is_empty()
    }));
}

#[test]
fn kong_dispatch_rejects_near_matches() {
    let untagged = temp_repo(
        "kong-untagged-command",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import (
    "github.com/alecthomas/kong"
    "os"
)
type Command struct{}
func (Command) Run() error { return os.RemoveAll("/untagged") }
type CLI struct { Command Command }
func main() { cli := &CLI{}; ctx := kong.Parse(cli); ctx.Run() }
"#,
            ),
        ],
    );
    assert!(resources(&build_index(&untagged, IndexLimits::default()), "main.go").is_empty());

    let local = temp_repo(
        "kong-local-lookalike",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                r#"package main
import "os"
type Command struct{}
func (Command) Run() error { return os.RemoveAll("/local-lookalike") }
type CLI struct { Command Command `cmd:""` }
type Context struct{}
func Parse(*CLI) *Context { return &Context{} }
func (*Context) Run() error { return nil }
func main() { cli := &CLI{}; ctx := Parse(cli); ctx.Run() }
"#,
            ),
        ],
    );
    assert!(resources(&build_index(&local, IndexLimits::default()), "main.go").is_empty());

    let wrong_import = temp_repo(
        "kong-wrong-import",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "fakekong/kong.go",
                "package fakekong\ntype Context struct{}\nfunc Parse(any) *Context { return &Context{} }\nfunc (*Context) Run() error { return nil }\n",
            ),
            (
                "main.go",
                r#"package main
import (
    kong "example.com/app/fakekong"
    "os"
)
type Command struct{}
func (Command) Run() error { return os.RemoveAll("/wrong-import") }
type CLI struct { Command Command `cmd:""` }
func main() { cli := &CLI{}; ctx := kong.Parse(cli); ctx.Run() }
"#,
            ),
        ],
    );
    assert!(
        resources(
            &build_index(&wrong_import, IndexLimits::default()),
            "main.go"
        )
        .is_empty()
    );
}

#[test]
fn fire_dispatches_only_the_selected_component() {
    for call in ["fire.Fire(main)", "fire.Fire()"] {
        let source = format!(
            "import fire\nimport os\ndef main(): os.remove('/stale-main')\nmain = 1\nif __name__ == '__main__':\n    {call}\n"
        );
        let root = temp_repo("fire-rebound", &[("app.py", &source)]);
        let index = build_index(&root, IndexLimits::default());
        assert!(resources(&index, "app.py").is_empty(), "{call}");
    }

    for (call, expected, absent) in [
        ("fire.Fire(main)", vec!["/main"], vec!["/other", "/run"]),
        (
            "fire.Fire(Commands)",
            vec!["/run", "/clean"],
            vec!["/main", "/private"],
        ),
        (
            "fire.Fire()",
            vec!["/main", "/other"],
            vec!["/run", "/private"],
        ),
    ] {
        let source = format!(
            "import fire\nimport os\ndef main(): os.remove('/main')\ndef other(): os.remove('/other')\nclass Commands:\n    def run(self): os.remove('/run')\n    def clean(self): os.remove('/clean')\n    def _private(self): os.remove('/private')\nif __name__ == '__main__':\n    {call}\n"
        );
        let root = temp_repo("fire-component", &[("app.py", &source)]);
        let index = build_index(&root, IndexLimits::default());
        let found = resources(&index, "app.py");
        for path in expected {
            assert!(found.contains(&format!("fs:{path}")), "{call}: {found:?}");
        }
        for path in absent {
            assert!(!found.contains(&format!("fs:{path}")), "{call}: {found:?}");
        }
        let composition = index.composition("app.py").unwrap();
        assert!(
            composition
                .occurrence_effects
                .iter()
                .all(|effect| effect.assurance
                    == if call == "fire.Fire(main)" {
                        Assurance::Exact
                    } else {
                        Assurance::Alternatives
                    })
        );
        assert!(composition.occurrence_effects.iter().all(|effect| {
            effect
                .via_dispatch
                .as_ref()
                .is_some_and(|via| via.model == "fire")
        }));
    }
}

#[test]
fn argparse_nested_subparsers_dispatch_under_hasattr_guard() {
    let root = temp_repo(
        "argparse-nested-main",
        &[(
            "app.py",
            r#"import argparse
import os
def handle(args): os.remove('/nested-handler')
def unused(args): os.remove('/unused-handler')
def main():
    parser = argparse.ArgumentParser()
    groups = parser.add_subparsers()
    group = groups.add_parser('group')
    commands = group.add_subparsers()
    command = commands.add_parser('run')
    command.set_defaults(func=handle)
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
if __name__ == '__main__':
    raise SystemExit(main())
"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(resources(&index, "app.py"), vec!["fs:/nested-handler"]);
}

#[test]
fn importlib_boundaries_specialize_directory_patterns_across_calls() {
    let root = temp_repo(
        "plugin-path-composition",
        &[
            (
                "app.py",
                "from pathlib import Path\nfrom loader import load2\nif __name__ == '__main__':\n    for path in Path('plugins').rglob('__init__.py'):\n        load2(path)\n",
            ),
            (
                "loader.py",
                "import importlib.util\ndef load2(p):\n    load(p)\ndef load(path):\n    spec = importlib.util.spec_from_file_location('plugin', path)\n    module = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(module)\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("app.py").unwrap();
    assert!(
        composition
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "cross_module"
                && boundary.detail.contains("plugins/**/__init__.py")
                && boundary.detail.matches("; recovered path ").count() == 1),
        "{:?}",
        composition.boundaries
    );
}
