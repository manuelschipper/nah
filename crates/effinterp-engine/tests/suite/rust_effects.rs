//! Filesystem / network effect coverage for the Rust frontend: the std file,
//! socket, and `OpenOptions` APIs real programs (e.g. ripgrep) reach.
#![allow(clippy::disallowed_types)]

use effinterp_engine::Engine;
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

fn analyze(src: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "rust".to_string(),
            source: src.to_string(),
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

/// The resource path of the first effect with the given operation.
fn fs_path_of<'a>(plan: &'a Plan, op: &str) -> Option<&'a str> {
    let e = plan.effects.iter().find(|e| e.operation.0 == op)?;
    match &e.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn endpoint_of<'a>(plan: &'a Plan, op: &str) -> Option<(&'a str, Option<u16>)> {
    let e = plan.effects.iter().find(|e| e.operation.0 == op)?;
    match &e.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, port, .. },
        } => Some((host, *port)),
        _ => None,
    }
}

#[test]
fn read_to_string_literal_is_a_concrete_read() {
    let plan =
        analyze("use std::fs;\nfn main() {\n    let _ = fs::read_to_string(\"/etc/hosts\");\n}\n");
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/etc/hosts"));
}

#[test]
fn read_dir_is_a_read() {
    let plan = analyze("use std::fs;\nfn main() {\n    let _ = fs::read_dir(\"/var/log\");\n}\n");
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/var/log"));
}

#[test]
fn file_open_is_a_read() {
    let plan =
        analyze("use std::fs::File;\nfn main() {\n    let _ = File::open(\"/etc/passwd\");\n}\n");
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/etc/passwd"));
}

#[test]
fn file_create_is_a_write() {
    let plan = analyze("use std::fs::File;\nfn main() {\n    let _ = File::create(\"/x\");\n}\n");
    assert_eq!(fs_path_of(&plan, "filesystem.write"), Some("/x"));
}

#[test]
fn remove_dir_all_is_a_recursive_delete() {
    let plan = analyze(
        "use std::fs;\nfn main() {\n    let p = \"/scratch\";\n    let _ = fs::remove_dir_all(p);\n}\n",
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("a delete");
    assert_eq!(
        del.attributes["recursive"],
        effinterp_proto::AttrValue::Bool(true)
    );
}

#[test]
fn copy_is_a_read_of_src_and_write_of_dst() {
    let plan = analyze("use std::fs;\nfn main() {\n    let _ = fs::copy(\"/a\", \"/b\");\n}\n");
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/a"));
    assert_eq!(fs_path_of(&plan, "filesystem.write"), Some("/b"));
}

#[test]
fn use_self_and_nested_groups_resolve_std_effects() {
    let grouped = analyze(
        "use std::fs::{self, File}; fn main() { fs::copy(\"/a\", \"/b\"); File::open(\"/file\"); }",
    );
    assert_eq!(fs_path_of(&grouped, "filesystem.read"), Some("/a"));
    assert_eq!(fs_path_of(&grouped, "filesystem.write"), Some("/b"));
    assert!(grouped.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/file")
    }));

    let renamed = analyze(
        "use std::fs::{self as filesys}; fn main() { filesys::copy(\"/renamed-a\", \"/renamed-b\"); }",
    );
    assert_eq!(fs_path_of(&renamed, "filesystem.read"), Some("/renamed-a"));
    assert_eq!(fs_path_of(&renamed, "filesystem.write"), Some("/renamed-b"));

    let nested = analyze(
        "use std::{fs::{self, File}, path::Path}; fn main() { fs::copy(\"/nested-a\", \"/nested-b\"); File::open(Path::new(\"/nested-file\")); }",
    );
    assert!(nested.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/nested-file")
    }));
}

#[test]
fn function_body_use_items_resolve_in_nested_blocks() {
    let plan = analyze(
        "fn wipe() { { use std::fs; fs::remove_file(\"/nested-body\"); } } fn launch() { use std::process::Command; Command::new(\"touch\").arg(\"/command\").status(); } fn main() { wipe(); launch(); }",
    );
    assert_eq!(fs_path_of(&plan, "filesystem.delete"), Some("/nested-body"));
    assert!(ops(&plan).contains(&"process.exec"));
}

#[test]
fn open_options_with_write_is_a_write() {
    let plan = analyze(
        "use std::fs::OpenOptions;\nfn main() {\n    let _ = OpenOptions::new().write(true).create(true).open(\"/out.log\");\n}\n",
    );
    assert_eq!(fs_path_of(&plan, "filesystem.write"), Some("/out.log"));
    assert!(!ops(&plan).contains(&"filesystem.read"));
}

#[test]
fn open_options_read_only_is_a_read() {
    let plan = analyze(
        "use std::fs::OpenOptions;\nfn main() {\n    let _ = OpenOptions::new().read(true).open(\"/in.txt\");\n}\n",
    );
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/in.txt"));
    assert!(!ops(&plan).contains(&"filesystem.write"));
}

#[test]
fn open_options_write_false_stays_a_read() {
    let plan = analyze(
        "use std::fs::OpenOptions;\nfn main() {\n    let _ = OpenOptions::new().read(true).write(false).open(\"/in.txt\");\n}\n",
    );
    assert_eq!(fs_path_of(&plan, "filesystem.read"), Some("/in.txt"));
    assert!(!ops(&plan).contains(&"filesystem.write"));
}

#[test]
fn file_options_builder_is_recognized() {
    let plan = analyze(
        "use std::fs::File;\nfn main() {\n    let _ = File::options().append(true).open(\"/log\");\n}\n",
    );
    assert_eq!(fs_path_of(&plan, "filesystem.write"), Some("/log"));
}

#[test]
fn tcp_connect_literal_endpoint() {
    let plan = analyze(
        "use std::net::TcpStream;\nfn main() {\n    let _ = TcpStream::connect(\"127.0.0.1:8080\");\n}\n",
    );
    assert_eq!(
        endpoint_of(&plan, "network.connect"),
        Some(("127.0.0.1", Some(8080)))
    );
}

#[test]
fn tcp_listener_bind_literal_endpoint() {
    let plan = analyze(
        "use std::net::TcpListener;\nfn main() {\n    let _ = TcpListener::bind(\"0.0.0.0:9000\");\n}\n",
    );
    assert_eq!(
        endpoint_of(&plan, "network.listen"),
        Some(("0.0.0.0", Some(9000)))
    );
}

#[test]
fn rust_format_resolves_url_and_socket_endpoints() {
    let plan = analyze(
        r#"
use std::net::TcpStream;
const API: &str = "https://api.example.com";

fn main() {
    reqwest::blocking::get(format!("{API}/status"));
    let host = "db.internal";
    let port = 5432;
    TcpStream::connect(format!("{host}:{port}"));
}
"#,
    );
    assert!(plan.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme),
                port: None,
                path: Some(path),
            }
        } if effect.operation.0 == "network.request"
            && host == "api.example.com"
            && scheme == "https"
            && path == "/status"
    )));
    assert_eq!(
        endpoint_of(&plan, "network.connect"),
        Some(("db.internal", Some(5432)))
    );
    assert!(!plan.boundaries.iter().any(|boundary| matches!(
        boundary.reason.as_str(),
        "unexpanded_macro" | "unmodeled_dynamic"
    )));
}

#[test]
fn rust_env_names_resolve_through_bound_parameters() {
    let plan = analyze(
        r#"
fn read_env(name: &str) {
    std::env::var(name);
}

fn main() {
    read_env("DATABASE_URL");
    let dynamic = unknown();
    read_env(dynamic);
}
"#,
    );
    let resources: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "environment.read")
        .map(|effect| &effect.resource)
        .collect();
    assert!(resources.iter().any(|resource| matches!(resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "DATABASE_URL"
    )));
    assert!(resources.iter().any(|resource| matches!(resource,
        ResourceExpr::Unresolved { family } if family.0 == "environment"
    )));
}

#[test]
fn symbolic_connect_stays_symbolic_not_concrete() {
    // A non-literal address is not invented as a concrete endpoint; it widens
    // to the unresolved network family.
    let plan = analyze(
        "use std::net::TcpStream;\nfn main() {\n    let addr = compute_addr();\n    let _ = TcpStream::connect(&addr);\n}\n",
    );
    let e = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "network.connect")
        .expect("a connect");
    assert!(
        matches!(&e.resource, ResourceExpr::Unresolved { family } if family.0 == "network"),
        "expected unresolved network, got {:?}",
        e.resource
    );
}

#[test]
fn reqwest_and_tcp_do_not_degrade_coverage() {
    // Modeled net APIs raise no unresolved_call boundary.
    let plan = analyze(
        "use std::net::TcpStream;\nfn main() {\n    let _ = TcpStream::connect(\"10.0.0.1:22\");\n    let _ = reqwest::blocking::get(\"https://host/x\");\n}\n",
    );
    assert!(ops(&plan).contains(&"network.connect"));
    assert!(ops(&plan).contains(&"network.request"));
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unresolved_call"),
        "boundaries: {:?}",
        plan.boundaries
    );
}

#[test]
fn command_preserves_structured_pager_candidates_and_ordered_arguments() {
    let plan = analyze(
        r#"
use std::process::Command;

struct Pager { bin: String, args: Vec<String> }

fn get_pager() -> Result<Option<Pager>, ()> {
    let pager = match std::env::var("PAGER") {
        Ok(bin) => Pager { bin, args: vec!["--env".to_string()] },
        Err(_) => Pager { bin: "less".to_string(), args: vec!["-R".to_string()] },
    };
    Ok(Some(pager))
}

fn resolve_binary(bin: &str) -> Result<String, ()> {
    Ok(bin.to_owned())
}

fn main() {
    let pager = match get_pager().unwrap() {
        Some(pager) => pager,
        None => return,
    };
    let resolved = resolve_binary(&pager.bin).unwrap();
    let mut command = Command::new(resolved);
    command.args(pager.args);
    command.status();
}
"#,
    );
    let processes: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if effect.operation.0 == "process.exec" => Some((executable.as_str(), argv)),
            _ => None,
        })
        .collect();
    assert_eq!(processes.len(), 1);
    assert!(processes.iter().any(|(executable, argv)| {
        *executable == "less"
            && matches!(argv.as_slice(), [ResourceExpr::Literal { value }] if value == "-R")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(effect.resource, ResourceExpr::Unresolved { ref family } if family.0 == "process")
    }));
}

#[test]
fn bound_command_builder_chains_apply_each_argument_once() {
    let plan = analyze(
        r#"
use std::process::Command;

fn main() {
    let mut command = Command::new("jobctl");
    command
        .arg("pipeline")
        .args(vec!["run".to_string(), "--detach".to_string()])
        .current_dir("/tmp")
        .status();
}
"#,
    );
    let processes: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if effect.operation.0 == "process.exec" => Some((executable.as_str(), argv)),
            _ => None,
        })
        .collect();
    assert_eq!(processes.len(), 1, "effects: {:?}", plan.effects);
    assert!(matches!(processes.as_slice(), [(executable, argv)]
        if *executable == "jobctl"
            && matches!(argv.as_slice(), [
                ResourceExpr::Literal { value: first },
                ResourceExpr::Literal { value: second },
                ResourceExpr::Literal { value: third },
            ] if first == "pipeline" && second == "run" && third == "--detach")));
}

#[test]
fn command_current_dir_controls_exec_and_nested_git_resources() {
    let plan = analyze(
        r#"
use std::process::Command;

fn main() {
    Command::new("git")
        .arg("pull")
        .current_dir("/srv/repo")
        .status();
}
"#,
    );
    let process = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "process.exec")
        .expect("process exec");
    assert!(matches!(&process.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::Process { cwd: Some(cwd), .. }
    } if matches!(cwd.as_ref(), ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path }
    } if path == "/srv/repo")));
    for operation in ["git.remote_sync", "git.worktree_write"] {
        assert!(plan.effects.iter().any(|effect| matches!(&effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::GitRepository { worktree: Some(worktree), .. }
            } if effect.operation.0 == operation
                && matches!(worktree.as_ref(), ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/srv/repo")
        )));
    }
    let exec = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(&node.subject,
            effinterp_proto::Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("git"))
        })
        .expect("git exec node");
    assert!(matches!(&exec.subject,
        effinterp_proto::Subject::Exec { cwd: Some(cwd), .. } if cwd == "/srv/repo"));
    assert!(matches!(&exec.cwd, Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path }
    }) if path == "/srv/repo"));
}

#[test]
fn command_current_dir_substitutes_parameters_and_default_cwd_is_unchanged() {
    let plan = analyze(
        r#"
use std::process::Command;

fn run(repo: &str) {
    Command::new("pwd").current_dir(repo).status();
}

fn main() {
    run("/srv/repo");
    Command::new("true").status();
}
"#,
    );
    for (executable, expected_cwd) in [("pwd", "/srv/repo"), ("true", "/work")] {
        let exec = plan
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(&node.subject,
                effinterp_proto::Subject::Exec { argv, .. }
                    if argv.first().map(String::as_str) == Some(executable))
            })
            .unwrap_or_else(|| panic!("{executable} exec node"));
        assert!(matches!(&exec.subject,
            effinterp_proto::Subject::Exec { cwd: Some(cwd), .. } if cwd == expected_cwd));
        assert!(matches!(&exec.cwd, Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }) if path == expected_cwd));
    }
}

#[test]
fn command_current_dir_branch_does_not_substitute_missing_cwd() {
    let plan = analyze(
        r#"
use std::process::Command;

fn run(cwd: &str, use_override: bool) {
    let mut command = Command::new("git");
    if use_override {
        command.current_dir("/srv/repo");
    }
    command.arg("pull").status();
}

fn main() {
    run("/unrelated", true);
}
"#,
    );
    let process = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "process.exec")
        .expect("process exec");
    assert!(matches!(&process.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::Process { cwd: Some(cwd), .. }
    } if matches!(cwd.as_ref(), ResourceExpr::Unresolved { family }
        if family.0 == "filesystem")));
    let exec = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(&node.subject,
                effinterp_proto::Subject::Exec { argv, .. }
                    if argv.first().map(String::as_str) == Some("git"))
        })
        .expect("git exec node");
    assert!(
        matches!(&exec.cwd, Some(ResourceExpr::Unresolved { family })
        if family.0 == "filesystem")
    );
    for operation in ["git.remote_sync", "git.worktree_write"] {
        assert!(plan.effects.iter().any(|effect| matches!(&effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::GitRepository { worktree: Some(worktree), .. }
            } if effect.operation.0 == operation
                && matches!(worktree.as_ref(), ResourceExpr::Unresolved { family }
                    if family.0 == "filesystem")
        )));
    }
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn rebound_command_builder_chains_apply_each_argument_once() {
    let plan = analyze(
        r#"
use std::process::Command;

fn main() {
    let mut command = Command::new("jobctl");
    let mut staged = command
        .arg("pipeline")
        .args(vec!["run".to_string()]);
    staged = staged.arg("--detach");
    staged.current_dir("/tmp").status();
}
"#,
    );
    let processes: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if effect.operation.0 == "process.exec" => Some((executable.as_str(), argv)),
            _ => None,
        })
        .collect();
    assert_eq!(processes.len(), 1, "effects: {:?}", plan.effects);
    assert!(matches!(processes.as_slice(), [(executable, argv)]
        if *executable == "jobctl"
            && matches!(argv.as_slice(), [
                ResourceExpr::Literal { value: first },
                ResourceExpr::Literal { value: second },
                ResourceExpr::Literal { value: third },
            ] if first == "pipeline" && second == "run" && third == "--detach")));
}

#[test]
fn command_builder_alias_mutation_invalidates_the_original() {
    let plan = analyze(
        r#"
use std::process::Command;

fn main() {
    let mut command = Command::new("jobctl");
    let staged = command.arg("pipeline");
    staged.arg("--detach");
    command.status();
}
"#,
    );
    assert!(!plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if effect.operation.0 == "process.exec" && executable == "jobctl")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn option_try_preserves_structured_command_values() {
    let plan = analyze(
        r#"
use std::process::Command;

struct Pager { bin: String, args: Vec<String> }

fn get_pager() -> Option<Pager> {
    Some(Pager {
        bin: "less".to_string(),
        args: vec!["-R".to_string()],
    })
}

fn run() -> Option<()> {
    let pager = get_pager()?;
    Command::new(pager.bin).args(pager.args).status();
    Some(())
}

fn main() { let _ = run(); }
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, argv, .. }
        } if effect.operation.0 == "process.exec"
            && executable == "less"
            && matches!(argv.as_slice(), [ResourceExpr::Literal { value }] if value == "-R"))
    }));
}

#[test]
fn repeated_helper_calls_keep_independent_branch_choices() {
    let plan = analyze(
        r#"
use std::process::Command;

struct Pager { bin: String, arg: String }

fn make(enabled: bool) -> Pager {
    let pair = if enabled {
        ("less".to_string(), "-R".to_string())
    } else {
        ("more".to_string(), "-X".to_string())
    };
    let (bin, arg) = pair;
    Pager { bin, arg }
}

fn main() {
    let first = make(true);
    let second = make(false);
    Command::new(first.bin).arg(second.arg).status();
}
"#,
    );
    let processes: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if effect.operation.0 == "process.exec" => Some((executable.as_str(), argv)),
            _ => None,
        })
        .collect();
    assert_eq!(processes.len(), 4, "effects: {:?}", plan.effects);
    assert!(processes.iter().any(|(executable, argv)| {
        *executable == "less"
            && matches!(argv.as_slice(), [ResourceExpr::Literal { value }] if value == "-X")
    }));
}

#[test]
fn command_candidate_overflow_widens_the_process_effect() {
    let plan = analyze(
        r#"
use std::process::Command;
fn main() {
    let mut command = Command::new("less");
    if std::env::var("A").is_ok() { command.arg("--a"); }
    if std::env::var("B").is_ok() { command.arg("--b"); }
    if std::env::var("C").is_ok() { command.arg("--c"); }
    if std::env::var("D").is_ok() { command.arg("--d"); }
    if std::env::var("E").is_ok() { command.arg("--e"); }
    if std::env::var("F").is_ok() { command.arg("--f"); }
    if std::env::var("G").is_ok() { command.arg("--g"); }
    command.status();
}
"#,
    );
    let processes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "process.exec")
        .collect();
    assert_eq!(processes.len(), 64);
    assert!(processes.iter().any(|effect| {
        matches!(effect.resource, ResourceExpr::Unresolved { ref family } if family.0 == "process")
    }));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| { boundary.domains == vec![effinterp_proto::Domain::new("process")] })
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&effinterp_proto::Domain::new("process"))
            .map(|claim| &claim.level),
        Some(&effinterp_proto::CoverageLevel::Partial)
    );
}

#[test]
fn mutations_invalidate_recovered_command_values() {
    let sources = [
        r#"
use std::process::Command;
struct Pager { bin: String }
fn main() {
    let mut pager = Pager { bin: "less".to_string() };
    pager.bin = "more".to_string();
    Command::new(pager.bin).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    bin.push_str("pipe");
    let mut args = vec!["-R".to_string()];
    args.push("-X".to_string());
    Command::new(bin).args(args).status();
}
"#,
        r#"
use std::process::Command;
fn decorate(command: &mut Command) { command.arg("--secret"); }
fn main() {
    let mut command = Command::new("less");
    decorate(&mut command);
    command.status();
}
"#,
        r#"
use std::process::Command;
trait Flags { fn add_flags(&mut self); }
impl Flags for Command { fn add_flags(&mut self) { self.arg("--secret"); } }
fn main() {
    let mut command = Command::new("less");
    command.add_flags();
    command.status();
}
"#,
        r#"
use std::process::Command;
trait Flags { fn add_flags(&mut self) -> &mut Command; }
impl Flags for Command {
    fn add_flags(&mut self) -> &mut Command { self.arg("--secret") }
}
fn main() {
    Command::new("less")
        .arg("-R")
        .add_flags()
        .arg("-F")
        .status();
}
"#,
        r#"
use std::os::unix::process::CommandExt;
use std::process::Command;
fn main() {
    let mut command = Command::new("less");
    command.arg0("rm");
    command.status();
}
"#,
        r#"
use std::process::Command;
struct Helper;
impl Helper { fn decorate(&self, bin: &mut String) { bin.push_str("pipe"); } }
fn main() {
    let mut bin = "less".to_string();
    Helper.decorate(&mut bin);
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    let alias = &mut bin;
    alias.push_str("pipe");
    Command::new(bin).status();
}
"#,
        r#"
use std::fmt::Write;
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    write!(bin, "pipe").unwrap();
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    bin += "-suffix";
    let mut arg = "-R".to_string();
    arg += "X";
    Command::new(bin).arg(arg).status();
}
"#,
        r#"
use std::process::Command;
struct Pager { bin: String }
fn main() {
    let mut pager = Pager { bin: "less".to_string() };
    pager.bin += "-suffix";
    Command::new(pager.bin).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    let mut replace = || { bin = "rm".to_string(); };
    replace();
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    let replace = || { bin = "rm".to_string(); };
    let alias = replace;
    alias();
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn apply<F: FnOnce()>(callback: F) { callback(); }
fn main() {
    let mut bin = "less".to_string();
    apply(|| { bin = "rm".to_string(); });
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn apply<F: FnOnce()>(callback: F) { callback(); }
fn main() {
    let mut bin = "less".to_string();
    let replace = || { bin = "rm".to_string(); };
    apply(replace);
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn apply<F: FnOnce()>(callback: F) { callback(); }
fn main() {
    let mut bin = "less".to_string();
    apply(|| { apply(|| { bin = "rm".to_string(); }); });
    Command::new(bin).status();
}
"#,
    ];

    for source in sources {
        let plan = analyze(source);
        assert!(!plan.effects.iter().any(|effect| {
            matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "less")
        }));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "process")
        }));
        assert_eq!(
            plan.coverage
                .0
                .get(&effinterp_proto::Domain::new("process"))
                .map(|claim| &claim.level),
            Some(&effinterp_proto::CoverageLevel::Partial)
        );
    }
}

#[test]
fn closure_and_index_mutations_do_not_publish_stale_arguments() {
    let sources = [
        r#"
use std::process::Command;
fn main() {
    let mut command = Command::new("less");
    let mut add = |arg: &str| { command.arg(arg); };
    add("-R");
    add("--danger");
    command.status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut args = vec!["-R".to_string()];
    args[0] += "X";
    Command::new("less").args(args).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    [1, 2].iter().for_each(|_| { bin = "rm".to_string(); });
    Command::new(bin).status();
}
"#,
        r#"
use std::process::Command;
fn apply<F: FnOnce()>(callback: F) { callback(); }
fn main() {
    let mut args = vec!["-R".to_string()];
    apply(|| { args = vec!["-X".to_string()]; });
    Command::new("less").args(args).status();
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut args = vec!["-R".to_string()];
    [1].iter().for_each(|_| {
        [2].iter().for_each(|_| { args = vec!["-X".to_string()]; });
    });
    Command::new("less").args(args).status();
}
"#,
    ];

    for source in sources {
        let plan = analyze(source);
        assert!(!plan.effects.iter().any(|effect| {
            matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. }
            } if executable == "less"
                && (argv.is_empty()
                    || matches!(argv.as_slice(), [ResourceExpr::Literal { value }]
                        if value == "-R")))
        }));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && (matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "process")
                    || matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { executable, .. }
                    } if executable == "less"))
        }));
    }
}

#[test]
fn commands_before_loop_carried_value_changes_widen() {
    let sources = [
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    for _ in 0..2 {
        Command::new(bin.clone()).status();
        bin = "rm".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    while std::env::var("MORE").is_ok() {
        Command::new(bin.clone()).status();
        bin = "rm".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    loop {
        Command::new(bin.clone()).status();
        bin = "rm".to_string();
        break;
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    for _ in 0..2 {
        let current = bin.clone();
        Command::new(current).status();
        bin = "rm".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    while std::env::var("MORE").is_ok() {
        let current = bin.clone();
        Command::new(current).status();
        bin = "rm".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    loop {
        let current = bin.clone();
        Command::new(current).status();
        bin = "rm".to_string();
        break;
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    while let Ok(_) = std::env::var("MORE") {
        let current = bin.clone();
        Command::new(current).status();
        bin = "rm".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut bin = "less".to_string();
    for _ in 0..2 {
        {
            let current = bin.clone();
            Command::new(current).status();
        }
        bin = "rm".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut extra = "-R".to_string();
    for _ in 0..2 {
        let flag = extra.clone();
        Command::new("less").arg(flag).status();
        extra = "-X".to_string();
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut extras = vec!["-R".to_string()];
    for flag in extras.clone() {
        Command::new("less").arg(flag).status();
        extras = vec!["-X".to_string()];
    }
}
"#,
        r#"
use std::process::Command;
fn main() {
    let mut item = Some("less".to_string());
    while let Some(bin) = item.clone() {
        Command::new(bin).status();
        item = Some("rm".to_string());
    }
}
"#,
    ];

    for source in sources {
        let plan = analyze(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "process")
        }));
        assert!(plan.effects.iter().any(|effect| {
            matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "less")
        }));
        assert_eq!(
            plan.coverage
                .0
                .get(&effinterp_proto::Domain::new("process"))
                .map(|claim| &claim.level),
            Some(&effinterp_proto::CoverageLevel::Partial)
        );
    }
}

#[test]
fn scoped_bindings_do_not_replace_outer_command_values() {
    let plan = analyze(
        r#"
use std::process::Command;
fn main() {
    let block_bin = "cat".to_string();
    { let block_bin = "less".to_string(); }
    Command::new(block_bin).arg("--block").status();

    let unsafe_arg = "--outer".to_string();
    unsafe { let unsafe_arg = "--inner".to_string(); }
    Command::new("echo").arg(unsafe_arg).status();

    let if_bin = "printf".to_string();
    if std::env::var("PAGER").is_ok() { let if_bin = "bash".to_string(); }
    Command::new(if_bin).arg("--if").status();

    let match_bin = "sh".to_string();
    let choice = Some("zsh".to_string());
    match choice { Some(match_bin) => drop(match_bin), None => {} }
    Command::new(match_bin).arg("--match").status();
}
"#,
    );
    let processes: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if effect.operation.0 == "process.exec" => Some((executable.as_str(), argv)),
            _ => None,
        })
        .collect();
    for (executable, argument) in [
        ("cat", "--block"),
        ("echo", "--outer"),
        ("printf", "--if"),
        ("sh", "--match"),
    ] {
        assert!(processes.iter().any(|(actual, argv)| {
            *actual == executable
                && matches!(argv.as_slice(), [ResourceExpr::Literal { value }] if value == argument)
        }));
    }
    assert!(!processes.iter().any(|(executable, argv)| {
        matches!(*executable, "less" | "bash" | "zsh")
            || argv.iter().any(
                |argument| matches!(argument, ResourceExpr::Literal { value } if value == "--inner"),
            )
    }));
}

#[test]
fn let_condition_bindings_do_not_reuse_outer_values() {
    let plan = analyze(
        r#"
use std::process::Command;
fn unknown() -> Option<String> { external() }
fn main() {
    let if_bin = "less".to_string();
    if let Some(if_bin) = unknown() {
        Command::new(if_bin).status();
    }

    let while_bin = "more".to_string();
    while let Some(while_bin) = unknown() {
        Command::new(while_bin).status();
        break;
    }
}
"#,
    );
    assert!(!plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if matches!(executable.as_str(), "less" | "more"))
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn bare_unit_variants_filter_proven_dead_match_arms() {
    let plan = analyze(
        r#"
use std::process::Command;
enum Mode { Safe, Dangerous }
use Mode::*;
fn main() {
    let wrapped = Some("less".to_string());
    let option_bin = match wrapped {
        Some(bin) => bin,
        None => "rm".to_string(),
    };
    Command::new(option_bin).status();

    let mode = Mode::Safe;
    let mode_bin = match mode {
        Safe => "cat".to_string(),
        Dangerous => "rm".to_string(),
    };
    Command::new(mode_bin).status();
}
"#,
    );
    let executables: Vec<_> = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. },
            } if effect.operation.0 == "process.exec" => Some(executable.as_str()),
            _ => None,
        })
        .collect();
    assert!(executables.contains(&"less"), "effects: {:?}", plan.effects);
    assert!(executables.contains(&"cat"), "effects: {:?}", plan.effects);
    assert!(!executables.contains(&"rm"), "effects: {:?}", plan.effects);
}

#[test]
fn loop_argument_accumulation_widens_the_process_effect() {
    let plan = analyze(
        r#"
use std::process::Command;
fn main() {
    let mut command = Command::new("less");
    for flag in ["-R", "-X"] {
        command.arg(flag);
    }
    command.status();

    let mut repeated = Command::new("less");
    while std::env::var("MORE_FLAGS").is_ok() {
        repeated.arg("-R");
    }
    repeated.status();
}
"#,
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| { boundary.domains == vec![effinterp_proto::Domain::new("process")] })
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&effinterp_proto::Domain::new("process"))
            .map(|claim| &claim.level),
        Some(&effinterp_proto::CoverageLevel::Partial)
    );
}

#[test]
fn repeated_local_value_calls_stay_bounded() {
    let depth = 30;
    let mut source =
        format!("use std::process::Command;\nfn f{depth}(x: &str) -> String {{ x.to_owned() }}\n");
    for index in (0..depth).rev() {
        let next = index + 1;
        source.push_str(&format!(
            "fn f{index}(x: &str) -> String {{ let a = f{next}(x); let b = f{next}(&a); if x.is_empty() {{ a }} else {{ b }} }}\n"
        ));
    }
    source.push_str("fn main() { Command::new(f0(\"less\")).status(); }\n");

    let (plan, stats) = Engine::new()
        .analyze_with_stats(&Subject::Source {
            dialect: None,
            language: "rust".to_string(),
            source,
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    // Value facts are charged to the step budget. Each helper calls the next
    // one twice, so inferring a helper once per call is exponential in depth
    // and either exceeds this linear bound or saturates the budget.
    assert!(
        stats.steps <= 64 * (depth as u64 + 1),
        "Rust helper value facts were re-inferred per call: {} steps",
        stats.steps
    );
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.limit.is_none())
    );
    assert!(plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "less")
    }));
}

#[test]
fn unresolved_helpers_and_ambiguous_variants_do_not_promote_named_fields() {
    let plan = analyze(
        r#"
use std::process::Command;
struct Pager { bin: String }
struct PagerLike { bin: String }
enum Choice { Pager(Pager), Text(String) }
fn choose() -> Choice { external_choice() }
fn opaque(bin: &str) -> String { external_text(bin) }
fn main() {
    let unrelated = PagerLike { bin: "less".to_string() };
    let selected = match choose() {
        Choice::Pager(pager) => pager.bin,
        Choice::Text(text) => text,
    };
    let resolved = opaque(&selected);
    Command::new(resolved).status();
    drop(unrelated);
}
"#,
    );
    assert!(!plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "less")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(effect.resource, ResourceExpr::Unresolved { ref family } if family.0 == "process")
    }));
}

#[test]
fn unsupported_match_patterns_keep_an_unresolved_process_alternative() {
    let plan = analyze(
        r#"
use std::process::Command;
fn literal(value: &str) -> String {
    match value { "a" => String::from("literal"), _ => String::from("other") }
}
fn range(value: u32) -> String {
    match value { 0..=3 => String::from("range"), _ => String::from("other") }
}
fn slice(value: &[&str]) -> String {
    match value { ["a", ..] => String::from("slice"), _ => String::from("other") }
}
fn main() {
    Command::new(literal("a")).status();
    Command::new(range(1)).status();
    Command::new(slice(&["a"])).status();
}
"#,
    );
    let unresolved = plan
        .effects
        .iter()
        .filter(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family } if family.0 == "process")
        })
        .count();
    assert_eq!(unresolved, 3, "effects: {:?}", plan.effects);
}

fn one_effect<'a>(plan: &'a Plan, operation: &str) -> &'a effinterp_proto::Effect {
    let effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == operation)
        .collect();
    assert_eq!(effects.len(), 1, "{operation}: {:?}", plan.effects);
    effects[0]
}

fn assert_no_untyped_resource(plan: &Plan) {
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "untyped_resource")
    );
}

fn repository_path(resource: &Option<Box<ResourceExpr>>) -> Option<&str> {
    match resource.as_deref() {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) => Some(path),
        None => None,
        other => panic!("expected repository path: {other:?}"),
    }
}

#[test]
fn git2_open_and_open_bare_use_the_repository_path_field() {
    for (source, worktree_path, git_dir_path) in [
        (
            "fn main(){ let _ = git2::Repository::open(\"/srv/repo\"); }",
            Some("/srv/repo"),
            None,
        ),
        (
            "fn main(){ let _ = git2::Repository::open_bare(\"/srv/repo.git\"); }",
            None,
            Some("/srv/repo.git"),
        ),
    ] {
        let plan = analyze(source);
        let ResourceExpr::Concrete {
            identity:
                ResourceIdentity::GitRepository {
                    worktree,
                    git_dir,
                    pathspec: None,
                },
        } = &one_effect(&plan, "git.read").resource
        else {
            panic!("expected git repository: {:?}", plan.effects);
        };
        assert_eq!(repository_path(worktree), worktree_path);
        assert_eq!(repository_path(git_dir), git_dir_path);
        assert_no_untyped_resource(&plan);
    }
}

#[test]
fn git2_open_parameter_is_an_unresolved_git_resource() {
    let plan = analyze(
        "fn f(path: &str){ let _ = git2::Repository::open(path); } fn main(){ f(\"/srv/repo\"); }",
    );
    assert!(matches!(
        &one_effect(&plan, "git.read").resource,
        ResourceExpr::Unresolved { family } if family.0 == "git"
    ));
    assert_no_untyped_resource(&plan);
}

fn spawn_is_not_silent(plan: &Plan) {
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec"),
        "spawn must emit process.exec; ops={:?}",
        ops(plan)
    );
    let nested = plan.effects.iter().any(|effect| {
        effect.operation.0.starts_with("filesystem.")
            || effect.operation.0.starts_with("git.")
            || effect.operation.0.starts_with("network.")
    });
    if !nested {
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "uncomposed_subprocess"
                    || boundary.domains.iter().any(|domain| domain.0 == "process")
            }),
            "uncomposed spawn must be loud; boundaries={:?}",
            plan.boundaries
        );
    }
}

#[test]
fn rust_spawn_shapes_are_never_silent() {
    spawn_is_not_silent(&analyze(
        "fn main() { std::process::Command::new(\"rm\").args([\"-rf\", \"/tmp/x\"]).status(); }",
    ));
    spawn_is_not_silent(&analyze(
        "fn main() { let args = vec![\"-rf\", \"/tmp/x\"]; std::process::Command::new(\"rm\").args(args).status(); }",
    ));
    spawn_is_not_silent(&analyze(
        "fn run(args: &[&str]) { std::process::Command::new(\"git\").args(args).status(); }\nfn main() { run(&[\"push\", \"--force\"]); }",
    ));
}

#[test]
fn unknown_std_member_and_cleanup_do_not_erase_known_effects() {
    for source in [
        r#"fn main() { std::fs::remove_file("/known"); std::fs::File::unknown_member(); }"#,
        r#"fn main() { std::fs::remove_file("/known"); std::fs::read(); }"#,
        r#"fn main() { std::fs::remove_file("/known"); std::path::unknown_member(); }"#,
        r#"use std::fs; fn main() { fs::remove_file("/known"); fs::unknown_member(|| { std::fs::write("/callback", "x"); }); }"#,
        r#"mod nested { pub struct Cleanup; impl Drop for Cleanup { fn drop(&mut self) { std::fs::write("/cleanup", "x"); } } } fn main() { let cleanup = nested::Cleanup; std::fs::remove_file("/known"); }"#,
        r#"struct Cleanup; impl Drop for Cleanup { fn drop(&mut self) { std::fs::write("/cleanup", "x"); } } fn main() { let cleanup = Cleanup; std::fs::remove_file("/known"); }"#,
    ] {
        let plan = analyze(source);
        assert_eq!(fs_path_of(&plan, "filesystem.delete"), Some("/known"));
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_call"
                    && b.callee.is_some()
                    && !b.provenance.is_empty()),
            "{plan:?}"
        );
        assert!(
            !plan
                .coverage
                .is_full(&effinterp_proto::Domain::new("filesystem"))
        );
    }
}
