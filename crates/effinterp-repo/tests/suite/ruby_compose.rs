//! Ruby cross-file composition: gem-executable entrypoints resolving
//! `require "gemname"` onto the repo's own lib/ tree, class/method dispatch
//! through the flat require namespace, cycle safety, and the loud-boundary
//! discipline for unresolvable requires.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::Path;

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

// Direct analysis and module summaries see the same root calls. Report each
// occurrence once without hiding a repeated call or the imported file's call.
#[test]
fn ruby_root_call_boundaries_are_not_duplicated_by_composition() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-root-call-boundaries",
        &[
            ("main.rb", "ENV.keys\nENV.keys\nrequire_relative 'helper'\n"),
            ("helper.rb", "ENV.keys\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effinterp_repo::effective_surface(&index, "main.rb").unwrap();
    let calls: Vec<_> = surface
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason == "unresolved_call")
        .collect();
    assert_eq!(calls.len(), 3, "{calls:#?}");
    let spans: Vec<_> = calls
        .iter()
        .flat_map(|boundary| &boundary.provenance)
        .filter_map(|step| match step {
            effinterp_repo::ProvenanceStep::SourceSpan { file, start, end }
                if file == "main.rb" =>
            {
                Some((*start, *end))
            }
            _ => None,
        })
        .collect();
    assert_eq!(spans, [(0, 8), (9, 17)]);
    assert!(calls.iter().any(|boundary| boundary.provenance.iter().any(
        |step| matches!(step, effinterp_repo::ProvenanceStep::CrossFile { into, .. } if into == "helper.rb")
    )));
}

/// A gem executable (shebang, no extension) requiring the gem by name: the
/// require maps onto lib/, the umbrella file's require_relative loads the
/// class file, and `MyGem::Runner.new(...).run` dispatches into it — effects
/// originate in the defining file, with argument substitution.
#[test]
fn gem_executable_composes_through_lib_requires() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-gem-exe",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'mygem'\n\nexit MyGem::Runner.new('/var/lib/app').run\n",
            ),
            ("Gemfile", ""),
            ("lib/mygem.rb", "require_relative 'mygem/runner'\n"),
            (
                "lib/mygem/runner.rb",
                r#"module MyGem
  class Runner
    def initialize(root)
      @root = root
    end

    def run
      config = ENV["APP_CONFIG"]
      cleanup(@root)
      0
    end

    def cleanup(dir)
      FileUtils.rm_rf(dir)
    end
  end
end
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "environment.read"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("APP_CONFIG")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "lib/mygem/runner.rb"),
        "env read should originate in runner.rb: {:?}",
        report.effects
    );
    assert!(
        report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "lib/mygem/runner.rb"),
        "delete should compose through the method chain: {:?}",
        report.effects
    );
}

#[test]
fn cross_file_textual_concat_refolds_after_argument_binding() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-cross-file-text-concat",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'cleaner'\nCleaner.new.wipe('/tmp/job-', '42.log', '/tmp/plus-', '8.log')\n",
            ),
            ("Gemfile", ""),
            (
                "lib/cleaner.rb",
                "class Cleaner\n  def wipe(a, b, c, d)\n    File.delete(\"#{a}#{b}\")\n    File.delete(c + d)\n  end\nend\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = report
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effect.resource.clone())
        .collect();
    assert_eq!(
        resources,
        [
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/tmp/job-42.log".into(),
                },
            },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/tmp/plus-8.log".into(),
                },
            }
        ]
    );
}

#[test]
fn cross_file_symbolic_textual_fragments_do_not_insert_cwd() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-cross-file-symbolic-text-concat",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'cleaner'\nCleaner.new.wipe(ENV['HOME'], '/x')\n",
            ),
            ("Gemfile", ""),
            (
                "lib/cleaner.rb",
                "class Cleaner\n  def wipe(prefix, suffix)\n    File.delete(\"#{prefix}#{suffix}\")\n  end\nend\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    let resource = &report
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "filesystem.delete")
        .expect("delete")
        .resource;
    assert_eq!(
        resource,
        &ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: String::new()
                },
                ResourceExpr::Environment {
                    name: "HOME".into(),
                },
                ResourceExpr::Literal { value: "/x".into() },
            ],
        }
    );
}

/// Mutually requiring files terminate and still compose their effects.
#[test]
fn require_cycle_is_bounded_and_composes() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-require-cycle",
        &[
            (
                "exe/tool",
                "#!/usr/bin/env ruby\nrequire 'tool'\nTool::A.go\n",
            ),
            ("Gemfile", ""),
            ("lib/tool.rb", "require_relative 'tool/a'\n"),
            (
                "lib/tool/a.rb",
                "require_relative 'b'\nmodule Tool\n  class A\n    def self.go\n      Tool::B.write\n    end\n  end\nend\n",
            ),
            (
                "lib/tool/b.rb",
                "require_relative 'a'\nmodule Tool\n  class B\n    def self.write\n      File.write(\"/tmp/out\", \"x\")\n    end\n  end\nend\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "exe/tool")
        .expect("exe/tool analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.write"
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "lib/tool/b.rb"),
        "cycle must not prevent composition: {:?}",
        report.effects
    );
}

#[test]
fn unqualified_constant_resolves_only_through_the_shared_loader() {
    fn files(load_git: bool) -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'color'\nColor::Core.new.run\n",
            ),
            ("Gemfile", ""),
            (
                "lib/color.rb",
                if load_git {
                    "require 'color/core'\nrequire 'color/git'\n"
                } else {
                    "require 'color/core'\n"
                },
            ),
            (
                "lib/color/core.rb",
                "module Color\n  class Core\n    def run\n      Git.status\n    end\n  end\nend\n",
            ),
            (
                "lib/color/git.rb",
                "module Color\n  module Git\n    def self.status\n      Kernel.system('git status')\n    end\n  end\nend\n",
            ),
        ]
    }

    let positive = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-shared-loader-constant",
        &files(true),
    );
    let report = effects_of(&build_index(&positive, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "process.exec"
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "lib/color/git.rb"
    }));

    let negative = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-unloaded-constant",
        &files(false),
    );
    let report = effects_of(&build_index(&negative, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.is_empty());
}

/// A require of an unknown gem is a loud cross-module boundary — and never
/// invents effects.
#[test]
fn unknown_gem_require_is_a_boundary_not_effects() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-unknown-gem",
        &[
            (
                "exe/cli",
                "#!/usr/bin/env ruby\nrequire 'somegem'\nrequire_relative '../helper'\nSomegem::Cli.start(ARGV)\n",
            ),
            ("helper.rb", "require 'nestedgem'\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "exe/cli")
        .expect("exe/cli analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "an unresolvable gem must not invent effects: {:?}",
        report.effects
    );
    assert!(
        report.boundaries.iter().any(|b| b.reason == "cross_module"
            && b.detail.as_deref().is_some_and(|d| d.contains("somegem"))),
        "unresolvable require must be a loud boundary: {:?}",
        report.boundaries
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unmodeled_import"),
        "repository import boundaries must replace raw require boundaries: {:?}",
        report.boundaries
    );
    for (source_file, module) in [("exe/cli", "somegem"), ("helper.rb", "nestedgem")] {
        let imports: Vec<_> = index.composed["exe/cli"]
            .boundaries
            .iter()
            .filter(|boundary| {
                boundary.source_file.as_deref() == Some(source_file)
                    && boundary.callee.as_ref().is_some_and(|callee| {
                        callee.module == module && callee.symbol == "__module_init__"
                    })
            })
            .collect();
        assert_eq!(imports.len(), 1, "{imports:?}");
        assert_eq!(imports[0].reason, "cross_module");
    }
}

/// An unmodeled-but-recognized stdlib require is loud too, while a curated
/// inert one stays quiet.
#[test]
fn stdlib_requires_classify_inert_and_unmodeled() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-stdlib-requires",
        &[(
            "exe/cli",
            "#!/usr/bin/env ruby\nrequire 'set'\nrequire 'socket'\nputs 'hi'\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "exe/cli")
        .expect("exe/cli analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .boundaries
            .iter()
            .any(|b| b.reason == "external_unmodeled"
                && b.detail.as_deref().is_some_and(|d| d.contains("socket"))
                && b.domains
                    .iter()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == effinterp_proto::DOMAINS.into_iter().collect()),
        "effectful stdlib require must stay loud: {:?}",
        report.boundaries
    );
    assert!(
        !report
            .boundaries
            .iter()
            .any(|b| b.detail.as_deref().is_some_and(|d| d.contains("\"set\""))),
        "inert stdlib require must stay quiet: {:?}",
        report.boundaries
    );
}

/// Requiring a command-table class without a dispatch trigger must not fire
/// the registered commands.
#[test]
fn command_table_without_start_is_inert() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-cmd-inert",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'mygem/cli'\nputs 'hi'\n",
            ),
            ("Gemfile", ""),
            (
                "lib/mygem/cli.rb",
                r#"module MyGem
  class CLI
    desc "wipe", "remove cache"
    def wipe
      FileUtils.rm_rf("/never")
    end
  end
end
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"),
        "registered commands must not fire without start: {:?}",
        report.effects
    );
}

#[test]
fn same_file_inheritance_composes_from_a_namespaced_entrypoint() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-same-file-inheritance",
        &[(
            "exe/app",
            "#!/usr/bin/env ruby\nmodule App\n  class Base\n    def helper\n      FileUtils.rm_rf('/inherited')\n    end\n  end\n  class Runner < Base\n    def run\n      helper\n    end\n  end\nend\nApp::Runner.new.run\n",
        )],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/inherited")
        }),
        "{:?}",
        report.effects
    );
}

#[test]
fn thor_command_dispatch_requires_the_exact_coloaded_base() {
    let files = |framework: &'static str| {
        vec![
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'tool'\nTool::CLI.start\n",
            ),
            ("Gemfile", ""),
            (
                "lib/tool.rb",
                if framework == "thor" {
                    "require 'thor'\nrequire 'tool/cli'\nrequire 'tool/doctor'\n"
                } else {
                    "require 'not_thor'\nrequire 'tool/cli'\nrequire 'tool/doctor'\n"
                },
            ),
            (
                "lib/tool/cli.rb",
                r#"module Tool
  class CLI < Thor
    desc "copy", "copy config"
    def copy
      FileUtils.copy_file("/source", "/target")
      FileUtils.rm("/obsolete")
      Tool::Doctor.installed?
    end
  end
end
"#,
            ),
            (
                "lib/tool/doctor.rb",
                r#"module Tool
  class Doctor
    def self.installed?
      Kernel.system("type tool > /dev/null")
    end
  end
end
"#,
            ),
        ]
    };

    let positive = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-thor-exact",
        &files("thor"),
    );
    let index = build_index(&positive, IndexLimits::default());
    let report = effects_of(&index, "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    for operation in ["filesystem.write", "filesystem.delete"] {
        assert!(report.effects.iter().any(|effect| {
            effect.operation.as_str() == operation
                && effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "lib/tool/cli.rb"
        }));
    }
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "process.exec"
            && effect
                .origin
                .as_ref()
                .expect("effect origin")
                .source_file
                .as_str()
                == "lib/tool/doctor.rb"
    }));

    let negative = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-thor-wrong-import",
        &files("not_thor"),
    );
    let index = build_index(&negative, IndexLimits::default());
    let report = effects_of(&index, "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "a name-only Thor-shaped class must stay inert: {:?}",
        report.effects
    );
}

/// A command that launches work through a getter-typed manager in another
/// file composes the process spawn from the manager's file.
#[test]
fn getter_typed_manager_composes_process_spawn() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-mgr-spawn",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'mygem/cli'\nMyGem::CLI.start\n",
            ),
            ("Gemfile", ""),
            (
                "lib/mygem/cli.rb",
                r#"require_relative 'engine'
module MyGem
  class CLI
    desc "start", "run it"
    def start
      engine.start
    end

    no_tasks do
      def engine
        @engine ||= Engine.new
      end
    end
  end
end
"#,
            ),
            (
                "lib/mygem/engine.rb",
                r#"module MyGem
  class Engine
    def start
      Process.spawn("rm", "-rf", "/tmp/work")
    end
  end
end
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "exe/app")
        .expect("exe/app analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|e| {
            e.operation.as_str() == "process.exec"
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == "lib/mygem/engine.rb"
        }),
        "manager spawn must originate in engine.rb: {:?}",
        report.effects
    );
}

#[test]
fn autoload_is_exact_and_missing_evidence_does_not_find_the_class() {
    let files = |autoload: bool| {
        vec![
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'app'\nApp::Runner.new.run\n",
            ),
            ("Gemfile", ""),
            (
                "lib/app.rb",
                if autoload {
                    "module App\n  autoload :Runner, 'app/runner'\nend\n"
                } else {
                    "module App\nend\n"
                },
            ),
            (
                "lib/app/runner.rb",
                "module App\n  class Runner\n    def run\n      FileUtils.rm_rf('/autoloaded')\n    end\n  end\nend\n",
            ),
        ]
    };

    let positive = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-autoload-positive",
        &files(true),
    );
    let report = effects_of(&build_index(&positive, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource)
                .contains("/autoloaded")
    }));

    let negative = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-autoload-negative",
        &files(false),
    );
    let report = effects_of(&build_index(&negative, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "missing autoload dispatched: {report:?}"
    );
}

#[test]
fn qualified_constant_rejects_a_required_class_from_the_wrong_namespace() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-qualified-wrong-namespace",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'mygem'\nMyGem::Runner.new.run\n",
            ),
            ("Gemfile", ""),
            ("lib/mygem.rb", "require_relative 'mygem/alpha'\n"),
            (
                "lib/mygem/alpha.rb",
                "module Alpha\n  class Runner\n    def run\n      File.delete('/wrong-namespace')\n    end\n  end\nend\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "wrong namespace dispatched: {report:?}"
    );
}

#[test]
fn unloaded_qualified_class_is_a_cross_module_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-unloaded-qualified-class",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'mygem'\nMyGem::Runner.new.run\n",
            ),
            ("Gemfile", ""),
            ("lib/mygem.rb", "module MyGem\nend\n"),
            (
                "app/anything.rb",
                "module MyGem\n  class Runner\n    def run\n      File.delete('/unloaded')\n    end\n  end\nend\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "unloaded class dispatched: {report:?}"
    );
    assert!(
        report.boundaries.iter().any(|boundary| {
            boundary.reason == "cross_module"
                && boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("MyGem::Runner"))
        }),
        "missing loader evidence was silent: {report:?}"
    );
}

#[test]
fn qualified_reopened_class_composes_across_required_files() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-qualified-reopened-class",
        &[
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'mygem'\nMyGem::Engine.new.run\n",
            ),
            ("Gemfile", ""),
            (
                "lib/mygem.rb",
                "require_relative 'mygem/core'\nrequire_relative 'mygem/extras'\n",
            ),
            (
                "lib/mygem/core.rb",
                "module MyGem\n  class Engine\n    def run\n      cleanup\n    end\n  end\nend\n",
            ),
            (
                "lib/mygem/extras.rb",
                "module MyGem\n  class Engine\n    def cleanup\n      File.delete('/reopened')\n    end\n  end\nend\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/reopened")
        }),
        "reopened class method did not compose: {report:?}"
    );
}

#[test]
fn mixin_dispatch_requires_the_include_edge() {
    let files = |include: bool| {
        vec![
            (
                "exe/app",
                "#!/usr/bin/env ruby\nrequire 'app'\nApp::Runner.new.run\n",
            ),
            ("Gemfile", ""),
            (
                "lib/app.rb",
                if include {
                    "require 'app/cleanup'\nmodule App\n  class Runner\n    include Cleanup\n    def run\n      cleanup\n    end\n  end\nend\n"
                } else {
                    "require 'app/cleanup'\nmodule App\n  class Runner\n    def run\n      cleanup\n    end\n  end\nend\n"
                },
            ),
            (
                "lib/app/cleanup.rb",
                "module App\n  module Cleanup\n    def cleanup\n      FileUtils.rm_rf('/mixed-in')\n    end\n  end\nend\n",
            ),
        ]
    };

    let positive = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-mixin-positive",
        &files(true),
    );
    let report = effects_of(&build_index(&positive, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource).contains("/mixed-in")
    }));

    let negative = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-mixin-negative",
        &files(false),
    );
    let report = effects_of(&build_index(&negative, IndexLimits::default()), "exe/app")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "missing include dispatched: {report:?}"
    );
}

#[test]
fn ruby_load_path_evidence_composes_nonstandard_roots() {
    for (tag, init, extra) in [
        (
            "expand",
            "$LOAD_PATH.unshift(File.expand_path('../core', __dir__))",
            None,
        ),
        (
            "pathname",
            "dir = __dir__\nROOT = Pathname(dir).parent.join('core').realpath\n$LOAD_PATH.insert(0, ROOT.to_s)",
            None,
        ),
        ("shebang", "#!/usr/bin/ruby -I ../core", None),
        (
            "gemspec",
            "#!/usr/bin/ruby",
            Some((
                "app.gemspec",
                "Gem::Specification.new do |s|\n s.require_paths = ['core']\nend\n",
            )),
        ),
    ] {
        let run = format!("{init}\nrequire 'app/cleaner'\nApp::Cleaner.purge\n");
        let mut files = vec![
            ("bin/run.rb", run.as_str()),
            (
                "core/app/cleaner.rb",
                "module App\nclass Cleaner\ndef self.purge\nFile.delete('/cache')\nend\nend\nend\n",
            ),
        ];
        files.extend(extra);
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("ruby-load-path-{tag}"),
            &files,
        );
        let index = build_index(&root, IndexLimits::default());
        let report = effects_of(&index, "bin/run.rb")
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert!(
            report
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"
                    && effect
                        .origin
                        .as_ref()
                        .is_some_and(|origin| origin.source_file == "core/app/cleaner.rb")),
            "{tag}: {:?}",
            report
        );
        assert!(
            index.composed["bin/run.rb"]
                .occurrence_effects
                .iter()
                .any(
                    |occurrence| index.composed["bin/run.rb"].effects[occurrence.effect]
                        .effect
                        .operation
                        .0
                        == "filesystem.delete"
                        && occurrence.path == ["bin/run.rb", "core/app/cleaner.rb:Cleaner.purge"]
                ),
            "{tag}: {:?}",
            index.composed["bin/run.rb"].effects
        );
        assert!(
            report
                .boundaries
                .iter()
                .all(|boundary| boundary.reason != "cross_module"
                    && !(boundary.reason == "unresolved_call"
                        && boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("unshift")
                                || detail.contains("expand_path")
                                || detail.contains("Pathname")))),
            "{tag}: {:?}",
            report.boundaries
        );
    }
}

#[test]
fn ruby_gem_requires_have_one_named_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-gem-identity",
        &[
            (
                "run.rb",
                "#!/usr/bin/ruby\nrequire 'json'\nrequire 'nokogiri'\nrequire 'sorbet_runtime'\n",
            ),
            (
                "Gemfile.lock",
                "GEM\n  specs:\n    json (2.7.0)\n    nokogiri (1.16.0)\n    sorbet-runtime (0.6.1)\n\nDEPENDENCIES\n  nokogiri\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "run.rb")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert_eq!(
        report
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason != "frontend_partial")
            .count(),
        2,
        "{:?}",
        report.boundaries
    );
    assert!(report.boundaries.iter().all(|boundary| matches!(
        boundary.reason.as_str(),
        "external_unmodeled" | "frontend_partial"
    )));
    assert!(
        report
            .boundaries
            .iter()
            .any(
                |boundary| boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("nokogiri 1.16.0")
                        && detail.contains("Gemfile.lock"))
            )
    );
    let composition = index.composed.get("run.rb").unwrap();
    assert!(composition.boundaries.iter().any(|boundary| {
        boundary
            .callee
            .as_ref()
            .is_some_and(|callee| callee.module == "nokogiri" && callee.symbol == "__module_init__")
    }));
    for (tag, name, source) in [
        ("gemfile", "Gemfile", "gem 'nokogiri', '1.16.0'\n"),
        (
            "gemspec",
            "app.gemspec",
            "Gem::Specification.new do |s|\n s.add_dependency 'nokogiri', '1.16.0'\nend\n",
        ),
    ] {
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("ruby-gem-declaration-{tag}"),
            &[
                ("run.rb", "#!/usr/bin/ruby\nrequire 'nokogiri'\n"),
                (name, source),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let composition = index.composed.get("run.rb").unwrap();
        let imports: Vec<_> = composition
            .boundaries
            .iter()
            .filter(|boundary| {
                boundary
                    .callee
                    .as_ref()
                    .is_some_and(|callee| callee.module == "nokogiri")
            })
            .collect();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].reason, "external_unmodeled");
        assert!(imports[0].detail.contains(name));
    }
}

#[test]
fn ruby_load_path_ambiguity_never_guesses() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-load-path-ambiguous",
        &[
            (
                "run.rb",
                "$LOAD_PATH.push(File.join(__dir__, 'a'), File.join(__dir__, 'b'))\nrequire 'feature'\n",
            ),
            ("a/feature.rb", "File.delete('/a')\n"),
            ("b/feature.rb", "File.delete('/b')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "run.rb")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(report.effects.is_empty());
    assert_eq!(
        report
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason != "frontend_partial")
            .count(),
        1,
        "{:?}",
        report.boundaries
    );
    assert_eq!(report.boundaries[0].reason, "cross_module");
    assert!(
        report.boundaries[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("ambiguous across load paths a, b")
    );
}

#[test]
fn ruby_require_closure_load_paths_precede_repo_wide_and_conventional_roots() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-load-path-priority",
        &[
            (
                "bin/run.rb",
                "require_relative '../bootstrap/init'\nrequire 'feature'\nputs 'run'\n",
            ),
            (
                "bootstrap/init.rb",
                "dir = __dir__ || raise('missing directory')\nROOT = Pathname(dir).parent.join('core').realpath\nunless $LOAD_PATH.include?(ROOT.to_s)\n$LOAD_PATH.insert(0, ROOT.to_s)\nend\n",
            ),
            (
                "other_boot.rb",
                "$LOAD_PATH.unshift(File.join(__dir__, 'other'))\n",
            ),
            ("Gemfile", "gem 'local'\n"),
            ("core/feature.rb", "X = File.delete('/selected')\n"),
            ("other/feature.rb", "X = File.delete('/wrong')\n"),
            ("lib/feature.rb", "X = File.delete('/conventional')\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composed.get("bin/run.rb").unwrap();
    assert_eq!(
        composition
            .occurrence_effects
            .iter()
            .filter(
                |occurrence| composition.effects[occurrence.effect].effect.operation.0
                    == "filesystem.delete"
            )
            .map(|occurrence| occurrence.source_file.as_str())
            .collect::<Vec<_>>(),
        ["core/feature.rb"]
    );
    assert!(
        composition
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "cross_module"),
        "{:?}",
        composition.boundaries
    );
}

#[test]
fn ruby_shell_launch_paths_need_a_real_launch_and_literal_options() {
    for (tag, command, resolves) in [
        ("include", r#"ruby -I../core "$SCRIPT_PATH""#, true),
        ("rubylib", r#"RUBYLIB=../core ruby "$SCRIPT_PATH""#, true),
        (
            "export",
            "export RUBYLIB=../core\nruby \"$SCRIPT_PATH\"",
            true,
        ),
        (
            "unexported",
            "RUBYLIB=../core\nruby \"$SCRIPT_PATH\"",
            false,
        ),
        (
            "unset",
            "export RUBYLIB=../core\nunset RUBYLIB\nruby \"$SCRIPT_PATH\"",
            false,
        ),
        (
            "unset-reassigned",
            "export RUBYLIB=../core\nunset RUBYLIB\nRUBYLIB=../core\nruby \"$SCRIPT_PATH\"",
            false,
        ),
        (
            "exported-reassigned",
            "export RUBYLIB=../other\nRUBYLIB=../core\nruby \"$SCRIPT_PATH\"",
            true,
        ),
        (
            "unset-reexported",
            "export RUBYLIB=../other\nunset RUBYLIB\nexport RUBYLIB=../core\nruby \"$SCRIPT_PATH\"",
            true,
        ),
        (
            "read-reassigned",
            "export RUBYLIB=../other\nread RUBYLIB\nRUBYLIB=../core\nruby \"$SCRIPT_PATH\"",
            true,
        ),
        ("argument", r#"ruby "$SCRIPT_PATH" -I../core"#, false),
        ("unreached", r#"echo ruby -I../core "$SCRIPT_PATH""#, false),
        ("dynamic", r#"RUBYLIB=$UNPROVEN ruby "$SCRIPT_PATH""#, false),
    ] {
        let command = format!("SCRIPT_PATH=\"$(dirname \"$0\")/../run.rb\"\n{command}\n");
        let root = repo_test_fixture(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("ruby-shell-path-{tag}"),
            &[
                ("bin/launch.sh", command.as_str()),
                ("run.rb", "require 'feature'\nputs 'run'\n"),
                ("core/feature.rb", "X = File.delete('/selected')\n"),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let report = effects_of(&index, "run.rb")
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert_eq!(
            report
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            resolves,
            "{tag}: {report:?}, {:?}",
            index.launch_edges
        );
    }
}

// Shared require closures must not multiply load-path probing per execution root;
// this shape previously stalled both clean indexing and each incremental update.
// Loader probes are charged as repository work units, so the bound is counted
// work rather than wall-clock time.
#[test]
fn ruby_many_load_paths_keep_clean_and_incremental_indexing_bounded() {
    use effinterp_repo::{EntrypointOutcome, RepoChange, apply_changes, save_index};

    // Indexing this fixture charges about 393k work units; probing multiplied
    // per execution root costs orders of magnitude more.
    const WORK_BOUND: u64 = 1_000_000;
    fn within_work_bound(index: &effinterp_repo::RepoIndex) -> bool {
        !index.entrypoints.iter().any(|entry| {
            matches!(&entry.outcome, EntrypointOutcome::LimitReached { limit } if limit == "repository.max_repo_work_units")
        }) && !index
            .skipped
            .iter()
            .any(|skip| skip.reason == "repository.max_repo_work_units")
    }

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "ruby-many-load-paths",
        &[("setup.rb", "")],
    );
    let setup: String = (0..100)
        .map(|i| format!("$LOAD_PATH.unshift(File.join(__dir__, 'root{i}'))\n"))
        .collect();
    std::fs::write(root.join("setup.rb"), &setup).unwrap();
    for i in 0..200 {
        let imports: String = (1..=8)
            .map(|j| format!("require 'f{}'\n", (i + j) % 200))
            .collect();
        std::fs::write(
            root.join(format!("f{i}.rb")),
            format!("{imports}puts 'ok'\n"),
        )
        .unwrap();
    }
    std::fs::write(
        root.join("run.rb"),
        "require 'setup'\nrequire 'f0'\nrequire 'added'\nputs 'ok'\n",
    )
    .unwrap();
    let limits = IndexLimits::default();
    let mut bounded = limits.clone();
    bounded.repository.max_repo_work_units = WORK_BOUND;
    assert!(
        within_work_bound(&build_index(&root, bounded.clone())),
        "clean Ruby indexing exceeded {WORK_BOUND} work units"
    );
    // Non-default repository limits force a rebuild on update, so the
    // incremental half runs against a default-limit snapshot.
    let mut index = build_index(&root, limits.clone());
    assert!(
        index
            .registry
            .resolve_import(
                &index.registry.files["run.rb"],
                &index.registry.files["run.rb"].summary.imports[1],
            )
            .is_some()
    );

    // The budget caps charged loader work; the limit must surface on every
    // entrypoint rather than restart loader work.
    let mut limited = limits.clone();
    limited.repository.max_repo_work_units = 100_000;
    let partial = build_index(&root, limited);
    assert!(partial.entrypoints.iter().all(|entry| matches!(
        &entry.outcome,
        EntrypointOutcome::LimitReached { limit } if limit == "repository.max_repo_work_units"
    )));

    // A batch of edits must refresh loader evidence only after every source changed.
    let mut changes = Vec::new();
    for i in 0..8 {
        let path = format!("f{i}.rb");
        let source = std::fs::read_to_string(root.join(&path)).unwrap();
        std::fs::write(root.join(&path), format!("{source}require 'added'\n")).unwrap();
        changes.push(RepoChange::Modified(path));
    }
    std::fs::create_dir(root.join("root99")).unwrap();
    std::fs::write(root.join("root99/added.rb"), "X = File.delete('/added')\n").unwrap();
    changes.push(RepoChange::Added("root99/added.rb".into()));
    let report = apply_changes(&mut index, &root, &limits, &changes);
    let mut reextracted = report.reextracted.clone();
    reextracted.sort();
    let mut changed: Vec<String> = (0..8).map(|i| format!("f{i}.rb")).collect();
    changed.push("root99/added.rb".into());
    changed.sort();
    assert_eq!(reextracted, changed, "{report:?}");
    assert_eq!(
        save_index(&index),
        save_index(&build_index(&root, limits.clone()))
    );
    assert!(
        effinterp_repo::effective_surface(&index, "run.rb")
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation == "filesystem.delete" && effect.origin_file == "root99/added.rb"
            })
    );

    // A skipped file is still a dependency: cached misses must not hide its
    // effect on snapshot completeness when finalization adds candidate paths.
    std::fs::write(
        root.join("root99/added.rb"),
        format!("#{}\n", "x".repeat(10_000)),
    )
    .unwrap();
    let mut limited = bounded;
    limited.crawl.max_file_bytes = 8_000;
    let partial = build_index(&root, limited);
    assert!(within_work_bound(&partial));
    assert!(partial.skipped_dependencies["root99/added.rb"].contains(&"run.rb".to_string()));
}
