//! Rust cross-file composition: workspace bin -> lib crate resolution by
//! package name, impl-method dispatch through constructor-typed receivers
//! (including associated constructors and match-arm struct literals),
//! `pub use` re-export hubs, renamed type aliases, and the extension-trait
//! fallback. Negatives pin the soundness edges: an ambiguous trait method
//! must stay a dispatch boundary, a missing re-export must not invent a
//! call, and unmodeled effectful std calls stay loud.
#![allow(clippy::disallowed_methods)]

use effinterp_engine::Assurance;
use effinterp_proto::{CoverageLevel, ResourceExpr, ResourceIdentity, display_resource_with_scope};
use effinterp_repo::{IndexLimits, Selector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::antecedent_origins;

// A workspace binary reaches the sibling lib crate through its package name
// (`use my_lib::...` with `name = "my-lib"` — hyphens map to underscores).

/// Every occurrence a fact's roots derive from, walking the envelope graph
/// backwards the way explanation does.
#[test]
fn workspace_bin_resolves_lib_crate_by_package_name() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-workspace-bin-lib",
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\", \"my-lib\"]\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            (
                "app/src/main.rs",
                "use my_lib::engine::start;\nfn main() {\n    start();\n}\n",
            ),
            (
                "my-lib/Cargo.toml",
                "[package]\nname = \"my-lib\"\nversion = \"0.1.0\"\n",
            ),
            ("my-lib/src/lib.rs", "pub mod engine;\n"),
            (
                "my-lib/src/engine.rs",
                "pub fn start() {\n    std::fs::remove_file(\"/var/lib-crate.lock\");\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &Selector::parse("fs:/var/lib-crate.lock").unwrap(),
        None,
    );
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| {
            h.fact.entrypoint == "app/src/main.rs"
                && h.fact.operation.as_str() == "filesystem.delete"
        })
        .expect("bin -> lib crate call reaches the delete");
    assert!(
        antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
            .iter()
            .any(|origin| origin.contains("my-lib/src/engine.rs")),
        "provenance crosses into the lib crate: {:?}",
        report.provenance
    );
}

#[test]
fn pager_fields_and_exact_helper_returns_reach_command_across_files() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-pager-value-flow",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"pager-flow\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/main.rs",
                "mod binary;\nmod output;\nmod pager;\nfn main() { output::run(); }\n",
            ),
            (
                "src/pager.rs",
                r#"
pub struct Pager { pub bin: String, pub args: Vec<String> }
pub fn get_pager() -> Result<Option<Pager>, ()> {
    let pager = match std::env::var("PAGER") {
        Ok(bin) => Pager { bin, args: vec!["--env".to_string()] },
        Err(_) => Pager { bin: "less".to_string(), args: vec!["-R".to_string()] },
    };
    Ok(Some(pager))
}
"#,
            ),
            (
                "src/binary.rs",
                "pub fn resolve_binary(bin: &str) -> Result<String, ()> { Ok(bin.to_owned()) }\n",
            ),
            (
                "src/output.rs",
                r#"
use crate::binary::resolve_binary;
use crate::pager::get_pager;
use std::process::Command;
pub fn run() {
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
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index
        .composition("src/main.rs")
        .unwrap_or_else(|| panic!("entrypoints: {:?}", index.entrypoints));
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter(|effect| {
            composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.source_file == "src/output.rs"
            }) && matches!(
                effect.effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { .. }
                }
            )
        })
        .collect();
    assert_eq!(processes.len(), 1, "effects: {:?}", composition.effects);
    assert!(
        processes.iter().any(|effect| {
            matches!(&effect.effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. }
            } if executable == "less"
                && matches!(argv.as_slice(), [ResourceExpr::Literal { value }] if value == "-R"))
        }),
        "effects: {:?}",
        composition.effects
    );
    assert!(composition.effects.iter().any(|effect| {
        composition.occurrence_effects.iter().any(|occurrence| {
            composition.effects[occurrence.effect].effect.id == effect.effect.id
                && occurrence.source_file == "src/output.rs"
        }) && matches!(&effect.effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn transformed_match_result_does_not_reuse_the_scrutinee_value() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-transformed-match-result",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"transformed-match\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/main.rs",
                "mod output;\nmod tools;\nfn main() { output::run(); }\n",
            ),
            (
                "src/tools.rs",
                r#"
pub fn viewer() -> Option<String> { Some("less".to_string()) }
pub fn transform(_bin: String) -> String { "rm".to_string() }
"#,
            ),
            (
                "src/output.rs",
                r#"
use std::process::Command;
use crate::tools;
pub fn run() {
    let bin = match tools::viewer() {
        Some(bin) => tools::transform(bin),
        None => return,
    };
    Command::new(bin).arg("--x").status();
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index
        .composition("src/main.rs")
        .unwrap_or_else(|| panic!("entrypoints: {:?}", index.entrypoints));
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter(|effect| {
            composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.source_file == "src/output.rs"
            }) && effect.effect.operation.0 == "process.exec"
        })
        .collect();
    assert!(
        processes.iter().any(|effect| {
            matches!(&effect.effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. }
            } if executable == "rm"
                && matches!(argv.as_slice(), [ResourceExpr::Literal { value }]
                    if value == "--x"))
        }),
        "effects: {:?}",
        composition.effects
    );
    assert!(
        !processes.iter().any(|effect| {
            matches!(&effect.effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "less")
        }),
        "effects: {:?}",
        composition.effects
    );
}

#[test]
fn reused_cross_file_result_names_keep_their_process_sites_distinct() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-reused-process-result-names",
        &[
            (
                "src/main.rs",
                r#"
mod tools;
use std::process::Command;
fn main() {
    {
        let bin = tools::viewer();
        Command::new(bin).arg("--show").status();
    }
    {
        let bin = tools::eraser();
        Command::new(bin).arg("-rf").status();
    }
}
"#,
            ),
            (
                "src/tools.rs",
                r#"
pub fn viewer() -> String { "less".to_string() }
pub fn eraser() -> String { "rm".to_string() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter_map(|effect| match &effect.effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } => Some((executable.as_str(), argv.as_slice())),
            _ => None,
        })
        .collect();
    assert!(processes.iter().any(|(executable, argv)| {
        *executable == "less"
            && matches!(argv, [ResourceExpr::Literal { value }] if value == "--show")
    }));
    assert!(processes.iter().any(|(executable, argv)| {
        *executable == "rm" && matches!(argv, [ResourceExpr::Literal { value }] if value == "-rf")
    }));
    assert!(!processes.iter().any(|(executable, argv)| {
        (*executable == "rm"
            && matches!(argv, [ResourceExpr::Literal { value }] if value == "--show"))
            || (*executable == "less"
                && matches!(argv, [ResourceExpr::Literal { value }] if value == "-rf"))
    }));
}

#[test]
fn cross_file_composition_keeps_correlated_process_fields() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-correlated-helper-fields",
        &[
            (
                "src/main.rs",
                r#"
mod output;
mod pager;
fn main() {
    output::run();
}
"#,
            ),
            (
                "src/output.rs",
                r#"
use crate::pager;
use std::process::Command;
struct LocalPager { bin: String, arg: String }
fn local_pager() -> LocalPager {
    if std::env::var("USE_RM").is_ok() {
        LocalPager { bin: "rm".to_string(), arg: "--wipe".to_string() }
    } else {
        LocalPager { bin: "cat".to_string(), arg: "--show".to_string() }
    }
}
pub fn run() {
    let pager = pager::make();
    Command::new(pager.bin).arg(pager.arg).status();
    let pager = local_pager();
    Command::new(pager.bin).arg(pager.arg).status();
}
"#,
            ),
            (
                "src/pager.rs",
                r#"
pub struct Pager { pub bin: String, pub arg: String }
pub fn make() -> Pager {
    if std::env::var("USE_MORE").is_ok() {
        Pager { bin: "more".to_string(), arg: "-X".to_string() }
    } else {
        Pager { bin: "less".to_string(), arg: "-R".to_string() }
    }
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let mut processes: Vec<_> = composition
        .effects
        .iter()
        .filter_map(|effect| match &effect.effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } => {
                let argv = argv
                    .iter()
                    .map(|argument| match argument {
                        ResourceExpr::Literal { value } => Some(value.clone()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some((executable.clone(), argv))
            }
            _ => None,
        })
        .collect();
    processes.sort();
    processes.dedup();
    assert_eq!(
        processes,
        vec![
            ("cat".to_string(), vec!["--show".to_string()]),
            ("less".to_string(), vec!["-R".to_string()]),
            ("more".to_string(), vec!["-X".to_string()]),
            ("rm".to_string(), vec!["--wipe".to_string()]),
        ],
        "effects: {:?}",
        composition.effects
    );
}

#[test]
fn cross_file_composition_keeps_empty_argument_branches_correlated() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-correlated-empty-arguments",
        &[
            (
                "src/main.rs",
                r#"
mod pager;
use std::process::Command;
fn main() {
    let pager = pager::make();
    Command::new(pager.bin).args(pager.args).status();
}
"#,
            ),
            (
                "src/pager.rs",
                r#"
pub struct Pager { pub bin: String, pub args: Vec<String> }
pub fn make() -> Pager {
    if std::env::var("USE_MORE").is_ok() {
        Pager { bin: "more".to_string(), args: vec![] }
    } else {
        Pager { bin: "less".to_string(), args: vec!["-R".to_string()] }
    }
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let mut processes: Vec<_> = composition
        .effects
        .iter()
        .filter_map(|effect| match &effect.effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } => {
                let argv = argv
                    .iter()
                    .map(|argument| match argument {
                        ResourceExpr::Literal { value } => Some(value.clone()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some((executable.clone(), argv))
            }
            _ => None,
        })
        .collect();
    processes.sort();
    processes.dedup();
    assert_eq!(
        processes,
        vec![
            ("less".to_string(), vec!["-R".to_string()]),
            ("more".to_string(), vec![]),
        ],
        "effects: {:?}",
        composition.effects
    );
}

#[test]
fn repeated_cross_file_helper_calls_keep_independent_branch_choices() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-independent-helper-branches",
        &[
            (
                "src/main.rs",
                r#"
mod pager;
use std::process::Command;
fn main() {
    let first = pager::make(true);
    let second = pager::make(false);
    Command::new(first.bin).arg(second.arg).status();
}
"#,
            ),
            (
                "src/pager.rs",
                r#"
pub struct Pager { pub bin: String, pub arg: String }
pub fn make(enabled: bool) -> Pager {
    let pair = if enabled {
        ("less".to_string(), "-R".to_string())
    } else {
        ("more".to_string(), "-X".to_string())
    };
    let (bin, arg) = pair;
    Pager { bin, arg }
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    assert!(
        composition.effects.iter().any(|effect| {
            matches!(&effect.effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, argv, .. }
            } if executable == "less"
                && matches!(argv.as_slice(), [ResourceExpr::Literal { value }] if value == "-X"))
        }),
        "effects: {:?}",
        composition.effects
    );
}

#[test]
fn inner_scope_does_not_replace_a_cross_file_process_value() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-scoped-process-values",
        &[
            (
                "src/main.rs",
                r#"
mod pager;
use pager::Pager;
use std::process::Command;
fn main() {
    let pager = pager::get_pager();
    {
        let pager = Pager { bin: "rm".to_string(), args: vec!["-rf".to_string()] };
    }
    Command::new(pager.bin).args(pager.args).status();
}
"#,
            ),
            (
                "src/pager.rs",
                r#"
pub struct Pager { pub bin: String, pub args: Vec<String> }
pub fn get_pager() -> Pager {
    Pager { bin: "less".to_string(), args: vec!["-R".to_string()] }
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter_map(|effect| match &effect.effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } => Some((executable.as_str(), argv.as_slice())),
            _ => None,
        })
        .collect();
    assert!(processes.iter().any(|(executable, argv)| {
        *executable == "less" && matches!(argv, [ResourceExpr::Literal { value }] if value == "-R")
    }));
    assert!(!processes.iter().any(|(executable, _)| *executable == "rm"));
}

#[test]
fn bound_command_builder_chains_keep_cross_file_arguments_ordered() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-bound-command-builder-chain",
        &[
            (
                "src/main.rs",
                r#"
mod tool;
use std::process::Command;
fn main() {
    let executable = tool::binary();
    let mut command = Command::new(executable);
    command
        .arg("pipeline")
        .arg("run")
        .arg("--detach")
        .status();
}
"#,
            ),
            (
                "src/tool.rs",
                r#"
pub fn binary() -> String { "jobctl".to_string() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter_map(|effect| match &effect.effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if executable == "jobctl" => Some(argv.as_slice()),
            _ => None,
        })
        .collect();
    assert!(!processes.is_empty(), "effects: {:?}", composition.effects);
    assert!(processes.iter().all(|argv| matches!(
        argv,
        [
            ResourceExpr::Literal { value: first },
            ResourceExpr::Literal { value: second },
            ResourceExpr::Literal { value: third },
        ] if first == "pipeline" && second == "run" && third == "--detach"
    )));
}

#[test]
fn rebound_command_builder_chains_keep_cross_file_arguments_ordered() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-bound-command-builder-chain",
        &[
            (
                "src/main.rs",
                r#"
mod tool;
use std::process::Command;
fn main() {
    let executable = tool::binary();
    let mut command = Command::new(executable);
    let mut staged = command
        .arg("pipeline")
        .arg("run");
    staged = staged.arg("--detach");
    staged.status();
}
"#,
            ),
            (
                "src/tool.rs",
                r#"
pub fn binary() -> String { "jobctl".to_string() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter_map(|effect| match &effect.effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable, argv, ..
                    },
            } if executable == "jobctl" => Some(argv.as_slice()),
            _ => None,
        })
        .collect();
    assert!(!processes.is_empty(), "effects: {:?}", composition.effects);
    assert!(processes.iter().all(|argv| matches!(
        argv,
        [
            ResourceExpr::Literal { value: first },
            ResourceExpr::Literal { value: second },
            ResourceExpr::Literal { value: third },
        ] if first == "pipeline" && second == "run" && third == "--detach"
    )));
}

#[test]
fn command_builder_alias_mutation_invalidates_cross_file_original() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-command-builder-alias",
        &[
            (
                "src/main.rs",
                r#"
mod tool;
use std::process::Command;
fn main() {
    let executable = tool::binary();
    let mut command = Command::new(executable);
    let staged = command.arg("pipeline");
    staged.arg("--detach");
    command.status();
}
"#,
            ),
            (
                "src/tool.rs",
                r#"
pub fn binary() -> String { "jobctl".to_string() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let plan = index
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.entrypoint.id == "src/main.rs")
        .and_then(|entrypoint| entrypoint.plan())
        .unwrap();
    assert!(!plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "jobctl")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn command_receiver_mutation_invalidates_cross_file_candidates() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-command-receiver-mutation",
        &[
            (
                "src/main.rs",
                r#"
mod tool;
use std::process::Command;
trait Flags { fn add_flags(&mut self); }
impl Flags for Command { fn add_flags(&mut self) { self.arg("--detach"); } }
fn main() {
    let executable = tool::binary();
    let mut command = Command::new(executable);
    command.add_flags();
    command.status();
}
"#,
            ),
            (
                "src/tool.rs",
                r#"
pub fn binary() -> String { "jobctl".to_string() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let plan = index
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.entrypoint.id == "src/main.rs")
        .and_then(|entrypoint| entrypoint.plan())
        .unwrap();
    assert!(!plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "jobctl")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn chained_command_receiver_mutation_invalidates_cross_file_candidates() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-chained-command-receiver-mutation",
        &[
            (
                "src/main.rs",
                r#"
mod tool;
use std::process::Command;
trait Flags { fn add_flags(&mut self) -> &mut Command; }
impl Flags for Command {
    fn add_flags(&mut self) -> &mut Command { self.arg("--detach") }
}
fn main() {
    Command::new(tool::binary())
        .arg("-R")
        .add_flags()
        .status();
}
"#,
            ),
            (
                "src/tool.rs",
                r#"
pub fn binary() -> String { "jobctl".to_string() }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let plan = index
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.entrypoint.id == "src/main.rs")
        .and_then(|entrypoint| entrypoint.plan())
        .unwrap();
    assert!(!plan.effects.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "jobctl")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn caller_mutation_invalidates_cross_file_command_values() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-mutated-command-values",
        &[
            (
                "src/main.rs",
                r#"
mod pager;
use std::process::Command;
struct Decorator;
impl Decorator {
    fn decorate(&self, bin: &mut String, args: &mut Vec<String>) {
        bin.push_str("pipe");
        args.push("-X".to_string());
    }
}
fn main() {
    let mut bin = pager::bin();
    let mut args = pager::args();
    Decorator.decorate(&mut bin, &mut args);
    Command::new(bin).args(args).status();
}
"#,
            ),
            (
                "src/pager.rs",
                r#"
pub fn bin() -> String { "less".to_string() }
pub fn args() -> Vec<String> { vec!["-R".to_string()] }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    assert!(!composition.effects.iter().any(|effect| {
        matches!(&effect.effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "less")
    }));
    assert!(composition.effects.iter().any(|effect| {
        effect.effect.operation.0 == "process.exec"
            && matches!(&effect.effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn closure_arguments_invalidate_cross_file_command_values() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-closure-argument-mutation",
        &[
            (
                "src/main.rs",
                r#"
mod helper;
mod pager;
use std::process::Command;
fn main() {
    let mut bin = pager::bin();
    helper::apply(|| { helper::apply(|| { bin = "rm".to_string(); }); });
    Command::new(bin).status();
}
"#,
            ),
            (
                "src/helper.rs",
                "pub fn apply<F: FnOnce()>(callback: F) { callback(); }\n",
            ),
            (
                "src/pager.rs",
                "pub fn bin() -> String { \"less\".to_string() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    assert!(!composition.effects.iter().any(|effect| {
        matches!(&effect.effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "less")
    }));
    assert!(composition.effects.iter().any(|effect| {
        effect.effect.operation.0 == "process.exec"
            && matches!(&effect.effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "process")
    }));
}

#[test]
fn cross_file_command_candidate_overflow_widens_the_process_effect() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-command-candidate-overflow",
        &[
            (
                "src/main.rs",
                r#"
mod output;
fn a() -> &'static str { if std::env::var("A").is_ok() { "--a" } else { "" } }
fn b() -> &'static str { if std::env::var("B").is_ok() { "--b" } else { "" } }
fn c() -> &'static str { if std::env::var("C").is_ok() { "--c" } else { "" } }
fn d() -> &'static str { if std::env::var("D").is_ok() { "--d" } else { "" } }
fn e() -> &'static str { if std::env::var("E").is_ok() { "--e" } else { "" } }
fn f() -> &'static str { if std::env::var("F").is_ok() { "--f" } else { "" } }
fn g() -> &'static str { if std::env::var("G").is_ok() { "--g" } else { "" } }
fn main() { output::run(a(), b(), c(), d(), e(), f(), g()); }
"#,
            ),
            (
                "src/output.rs",
                r#"
use std::process::Command;
pub fn run(a: &str, b: &str, c: &str, d: &str, e: &str, f: &str, g: &str) {
    Command::new("less").arg(a).arg(b).arg(c).arg(d).arg(e).arg(f).arg(g).status();
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let processes: Vec<_> = composition
        .effects
        .iter()
        .filter(|effect| effect.effect.operation.0 == "process.exec")
        .collect();
    assert_eq!(processes.len(), 64);
    assert!(processes.iter().any(|effect| {
        matches!(effect.effect.resource, ResourceExpr::Unresolved { ref family }
            if family.0 == "process")
    }));
    assert!(
        composition
            .boundaries
            .iter()
            .any(|boundary| boundary.domains == ["process"])
    );
    assert!(
        composition
            .coverage
            .iter()
            .any(|(domain, level)| { domain == "process" && *level == CoverageLevel::Partial })
    );
}

/// `Type::new()` types the local, and a method call on it dispatches into the
/// impl block in another file — including a `self.<method>` hop inside it.
#[test]
fn impl_method_dispatch_through_constructor_typed_receiver() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-impl-dispatch",
        &[
            (
                "src/main.rs",
                "mod config;\nuse crate::config::Config;\nfn main() {\n    let c = Config::new();\n    c.apply();\n}\n",
            ),
            (
                "src/config.rs",
                concat!(
                    "pub struct Config;\n",
                    "impl Config {\n",
                    "    pub fn new() -> Self {\n",
                    "        std::fs::read_to_string(\"/etc/app.conf\").ok();\n",
                    "        Config\n",
                    "    }\n",
                    "    pub fn apply(&self) {\n",
                    "        self.wipe();\n",
                    "    }\n",
                    "    fn wipe(&self) {\n",
                    "        std::fs::remove_file(\"/var/app.lock\").ok();\n",
                    "    }\n",
                    "}\n",
                ),
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    for (selector, op) in [
        ("fs:/etc/app.conf", "filesystem.read"),
        ("fs:/var/app.lock", "filesystem.delete"),
    ] {
        let report = reach(&idx, &Selector::parse(selector).unwrap(), None);
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|h| h.fact.entrypoint == "src/main.rs" && h.fact.operation.as_str() == op),
            "{op} on {selector} reaches main: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn imported_receiver_in_cross_file_trait_impl_dispatches_exactly() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-cross-file-trait-receiver",
        &[
            (
                "src/main.rs",
                "mod ext;\nmod types;\nuse crate::ext::Ext;\nuse crate::types::Foo;\nfn main() { let value = Foo::new(); value.wipe_it(); }\n",
            ),
            (
                "src/types.rs",
                "pub struct Foo;\nimpl Foo { pub fn new() -> Foo { Foo } }\n",
            ),
            (
                "src/ext.rs",
                "use crate::types::Foo;\npub trait Ext { fn wipe_it(&self); }\nimpl Ext for Foo { fn wipe_it(&self) { std::fs::remove_file(\"/cross-file-trait\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    let effect = composition
        .effects
        .iter()
        .find(|effect| {
            display_resource_with_scope(&effect.effect.resource).contains("/cross-file-trait")
        })
        .expect("the imported receiver identity matches its cross-file trait impl");
    assert!(
        composition
            .occurrence_effects
            .iter()
            .filter(
                |occurrence| composition.effects[occurrence.effect].effect.id == effect.effect.id
            )
            .all(|occurrence| occurrence.assurance == Assurance::Exact)
    );
}

/// A typed trait receiver admits one evidence-backed fallback as heuristic;
/// a small candidate set enters every implementation as alternatives.
#[test]
fn trait_method_cardinality_sets_assurance() {
    let files = |second_impl: bool| {
        let mut v = vec![
            (
                "src/main.rs",
                "mod ext;\nmod other;\nuse crate::ext::Ext;\nfn main() {\n    let x: &dyn Ext = external_thing();\n    x.wipe_it();\n}\n",
            ),
            (
                "src/ext.rs",
                "pub trait Ext {\n    fn wipe_it(&self);\n}\nimpl Ext for String {\n    fn wipe_it(&self) {\n        std::fs::remove_file(\"/var/ext-a\").ok();\n    }\n}\n",
            ),
        ];
        v.push((
            "src/other.rs",
            if second_impl {
                "use crate::ext::Ext;\nimpl Ext for i64 {\n    fn wipe_it(&self) {\n        std::fs::remove_file(\"/var/ext-b\").ok();\n    }\n}\n"
            } else {
                "pub fn unused() {}\n"
            },
        ));
        v
    };

    // One impl: the extension call resolves to it.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-single",
        &files(false),
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/ext-a").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "src/main.rs"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "single trait impl resolves: {:?}",
        report.payload.as_reach().unwrap().matches
    );

    // Two impls: both resolve as alternatives.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-ambiguous",
        &files(true),
    );
    let idx = build_index(&root, IndexLimits::default());
    let effects = effects_of(&idx, "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(resources, ["fs:/var/ext-a", "fs:/var/ext-b"]);
    let composition = idx.composition("src/main.rs").unwrap();
    assert!(
        composition
            .occurrence_effects
            .iter()
            .filter(
                |occurrence| composition.effects[occurrence.effect].effect.operation.0
                    == "filesystem.delete"
            )
            .all(|occurrence| occurrence.assurance == Assurance::Alternatives)
    );
}

#[test]
fn same_method_on_wrong_trait_does_not_join_candidate_set() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-identity",
        &[
            (
                "src/main.rs",
                "mod right;\nmod wrong;\nuse crate::right::Right;\nfn main() { let x: &dyn Right = external_thing(); x.act(); }\n",
            ),
            (
                "src/right.rs",
                "pub trait Right { fn act(&self); }\nimpl Right for String { fn act(&self) { std::fs::remove_file(\"/right\").ok(); } }\n",
            ),
            (
                "src/wrong.rs",
                "pub trait Wrong { fn act(&self); }\nimpl Wrong for i64 { fn act(&self) { std::fs::remove_file(\"/wrong\").ok(); } }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let effects = effects_of(&idx, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/right"]);
}

#[test]
fn untyped_method_name_does_not_dispatch() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-untyped",
        &[
            (
                "src/main.rs",
                "mod ext;\nfn main() { let x = external_thing(); x.wipe_it(); }\n",
            ),
            (
                "src/ext.rs",
                "pub trait Ext { fn wipe_it(&self); }\nimpl Ext for String { fn wipe_it(&self) { std::fs::remove_file(\"/never\").ok(); } }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    assert!(
        effects_of(&idx, "src/main.rs")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    != "fs:/never"
            )
    );
}

#[test]
fn typed_external_receiver_resolves_its_repository_trait_impl() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-extension-trait",
        &[
            (
                "src/main.rs",
                "mod ext;\nuse crate::ext::CommandExt;\nfn main() { let command = ext::command().unwrap(); command.run_ext(); }\n",
            ),
            (
                "src/ext.rs",
                "use std::process::Command;\npub trait CommandExt { fn run_ext(&self); }\nimpl CommandExt for Command { fn run_ext(&self) { std::fs::remove_file(\"/extension\").ok(); } }\npub fn command() -> Result<Command, ()> { Ok(Command::new(\"echo\")) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    assert_eq!(composition.effects.len(), 1);
    assert_eq!(
        composition.occurrence_effects[0].assurance,
        Assurance::Exact
    );
    assert_eq!(
        composition.effects[0].effect.operation.0,
        "filesystem.delete"
    );
}

#[test]
fn std_receiver_trait_impl_precedes_inert_method_classification() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-std-receiver-trait-shadow",
        &[(
            "src/main.rs",
            "trait Weird { fn len(self); }\nimpl<T> Weird for Vec<T> { fn len(self) { std::fs::remove_file(\"/rust-std-trait-shadow\"); } }\nfn main() { let values: Vec<String> = Vec::new(); values.len(); }\n",
        )],
    );
    let effects = effects_of(&build_index(&root, IndexLimits::default()), "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();

    assert!(effects.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && display_resource_with_scope(&effect.resource) == "fs:/rust-std-trait-shadow"
    }));
}

#[test]
fn glob_reexport_preserves_external_trait_receiver_identity() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-extension-trait-glob",
        &[
            (
                "src/main.rs",
                "mod ext;\npub(crate) use std::process::Command;\nuse crate::ext::CommandExt;\nfn main() { let command = Command::resolve(); command.run_ext(); }\n",
            ),
            (
                "src/ext.rs",
                "use super::*;\npub trait CommandExt { fn resolve() -> Command; fn run_ext(&self); }\nimpl CommandExt for Command { fn resolve() -> Command { Command::new(\"echo\") } fn run_ext(&self) { std::fs::remove_file(\"/extension-glob\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(
        effects_of(&index, "src/main.rs")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/extension-glob"
            )
    );
    let composition = index.composition("src/main.rs").unwrap();
    assert!(composition.effects.iter().any(|effect| {
        effect.effect.operation.0 == "filesystem.delete"
            && composition.occurrence_effects.iter().any(|occurrence| {
                composition.effects[occurrence.effect].effect.id == effect.effect.id
                    && occurrence.assurance == Assurance::Exact
            })
    }));
}

/// Effectful-but-unmodeled std stays a loud external_unmodeled boundary;
/// curated pure std modules stay quiet (external_inert).
#[test]
fn unmodeled_std_call_is_a_loud_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-std-classify",
        &[(
            "src/main.rs",
            "use std::io::stdin;\nuse std::cmp::max;\nfn main() {\n    stdin();\n    max(1, 2);\n}\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let effects = effects_of(&idx, "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();
    let unmodeled = effects
        .boundaries
        .iter()
        .find(|b| {
            b.reason == "external_unmodeled"
                && b.detail.as_deref().unwrap_or("").contains("std::io::stdin")
        })
        .expect("std::io::stdin stays loud");
    assert!(
        !unmodeled.domains.is_empty(),
        "unmodeled std degrades coverage domains"
    );
    assert!(
        !effects
            .boundaries
            .iter()
            .any(|b| b.reason == "external_inert"),
        "quiet classifications are not protocol boundaries: {:?}",
        effects.boundaries
    );
    let composition = idx.composition("src/main.rs").unwrap();
    assert!(
        composition
            .boundaries
            .iter()
            .any(|b| b.reason == "external_inert" && b.detail.contains("std::cmp::max")),
        "pure std classifies inert: {:?}",
        composition.boundaries
    );
}

/// A Cargo binary whose source is only `framework::bin!(crate_name)` reaches
/// the crate library even when `[lib] path` is not `src/lib.rs`.
#[test]
fn bin_macro_reaches_lib_path_uumain() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-bin-macro-lib-path",
        &[
            (
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"uu_tool\"\nversion = \"0.1.0\"\n\n",
                    "[lib]\npath = \"src/tool.rs\"\n",
                ),
            ),
            ("src/main.rs", "framework::bin!(uu_tool);\n"),
            (
                "src/tool.rs",
                "pub fn uumain() {\n    std::fs::remove_file(\"/var/tool.lock\");\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let ids: Vec<_> = idx
        .entrypoints
        .iter()
        .map(|e| e.entrypoint.id.clone())
        .collect();
    assert!(
        ids.iter().any(|id| id == "src/main.rs"),
        "bin! file is a program entry: {ids:?}"
    );
    let report = reach(&idx, &Selector::parse("fs:/var/tool.lock").unwrap(), None);
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| {
            h.fact.entrypoint == "src/main.rs" && h.fact.operation.as_str() == "filesystem.delete"
        })
        .expect("bin! handoff reaches the library delete");
    assert!(
        antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
            .iter()
            .any(|origin| origin.contains("src/tool.rs")),
        "provenance crosses into the [lib] path file: {:?}",
        report.provenance
    );
}

/// An unrecognized item macro must not invent a crate handoff.
#[test]
fn unrecognized_macro_does_not_invent_a_crate_call() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-unrecognized-macro",
        &[
            (
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"uu_tool\"\nversion = \"0.1.0\"\n\n",
                    "[lib]\npath = \"src/tool.rs\"\n",
                ),
            ),
            ("src/main.rs", "fn main() {\n    trace!(uu_tool);\n}\n"),
            (
                "src/tool.rs",
                "pub fn uumain() {\n    std::fs::remove_file(\"/var/tool.lock\");\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let effects = effects_of(&idx, "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"),
        "trace! must not call uumain: {:?}",
        effects.effects
    );
}

/// A struct literal inside a `match` arm types the receiver so `exa.run()`
/// dispatches into the impl, including a later `Dir::read` through a hub.
#[test]
fn match_arm_constructor_reaches_impl_and_reexport() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-match-arm-ctor",
        &[
            (
                "src/main.rs",
                concat!(
                    "mod fs;\n",
                    "use crate::fs::Dir;\n",
                    "pub struct Exa;\n",
                    "impl Exa {\n",
                    "    pub fn run(&self) {\n",
                    "        let d = Dir::new();\n",
                    "        d.read();\n",
                    "    }\n",
                    "}\n",
                    "fn main() {\n",
                    "    match 0 {\n",
                    "        0 => {\n",
                    "            let exa = Exa {};\n",
                    "            exa.run();\n",
                    "        }\n",
                    "        _ => {}\n",
                    "    }\n",
                    "}\n",
                ),
            ),
            ("src/fs/mod.rs", "mod dir;\npub use self::dir::Dir;\n"),
            (
                "src/fs/dir.rs",
                concat!(
                    "pub struct Dir;\n",
                    "impl Dir {\n",
                    "    pub fn new() -> Dir { Dir }\n",
                    "    pub fn read(&self) {\n",
                    "        std::fs::read_dir(\"/var/listed-dir\").ok();\n",
                    "    }\n",
                    "}\n",
                ),
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/listed-dir").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "src/main.rs"
                && h.fact.operation.as_str() == "filesystem.read"),
        "match-arm Exa {{}} -> run -> Dir::read: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

/// A `mod.rs` hub that `pub use`s `File`/`Dir` from submodules lets the bin
/// call associated constructors and methods on those types. Without the
/// re-export the same `use crate::fs::File` must not invent a call.
#[test]
fn reexport_hub_resolves_type_to_defining_file() {
    let files = |reexport: bool| {
        vec![
            (
                "src/main.rs",
                "mod fs;\nuse crate::fs::{Dir, File};\nfn main() {\n    let f = File::from_args();\n    f.list();\n    let d = Dir::new();\n    d.read();\n}\n",
            ),
            (
                "src/fs/mod.rs",
                if reexport {
                    "mod dir;\npub use self::dir::Dir;\nmod file;\npub use self::file::File;\n"
                } else {
                    "mod dir;\nmod file;\n"
                },
            ),
            (
                "src/fs/file.rs",
                "pub struct File;\nimpl File {\n    pub fn from_args() -> File { File }\n    pub fn list(&self) {\n        std::fs::read_to_string(\"/var/listed\").ok();\n    }\n}\n",
            ),
            (
                "src/fs/dir.rs",
                "pub struct Dir;\nimpl Dir {\n    pub fn new() -> Dir { Dir }\n    pub fn read(&self) {\n        std::fs::read_dir(\"/var/dir\").ok();\n    }\n}\n",
            ),
        ]
    };

    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-reexport-hub",
        &files(true),
    );
    let idx = build_index(&root, IndexLimits::default());
    for (selector, op) in [
        ("fs:/var/listed", "filesystem.read"),
        ("fs:/var/dir", "filesystem.read"),
    ] {
        let report = reach(&idx, &Selector::parse(selector).unwrap(), None);
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|h| h.fact.entrypoint == "src/main.rs" && h.fact.operation.as_str() == op),
            "re-export hub reaches {selector}: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }

    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-reexport-hub-missing",
        &files(false),
    );
    let idx = build_index(&root, IndexLimits::default());
    let effects = effects_of(&idx, "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.read"),
        "no pub use must not invent File/Dir calls: {:?}",
        effects.effects
    );
}

/// `use theme::Options as ThemeOptions; ThemeOptions::deduce()` must follow
/// the renamed import, not recurse into a same-named local `Options`.
#[test]
fn renamed_import_assoc_fn_does_not_recurse_into_local_type() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-renamed-assoc",
        &[
            (
                "src/main.rs",
                concat!(
                    "mod options;\n",
                    "fn main() {\n",
                    "    options::Options::deduce();\n",
                    "}\n",
                ),
            ),
            (
                "src/options.rs",
                concat!(
                    "use crate::theme::Options as ThemeOptions;\n",
                    "pub struct Options;\n",
                    "impl Options {\n",
                    "    pub fn deduce() {\n",
                    "        ThemeOptions::deduce();\n",
                    "        std::fs::read_to_string(\"/var/opts\").ok();\n",
                    "    }\n",
                    "}\n",
                ),
            ),
            (
                "src/theme.rs",
                concat!(
                    "pub struct Options;\n",
                    "impl Options {\n",
                    "    pub fn deduce() {\n",
                    "        std::fs::read_to_string(\"/var/theme\").ok();\n",
                    "    }\n",
                    "}\n",
                ),
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    for selector in ["fs:/var/opts", "fs:/var/theme"] {
        let report = reach(&idx, &Selector::parse(selector).unwrap(), None);
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|h| h.fact.entrypoint == "src/main.rs"
                    && h.fact.operation.as_str() == "filesystem.read"),
            "renamed assoc fn reaches {selector}: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
    let effects = effects_of(&idx, "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .boundaries
            .iter()
            .any(|b| b.reason == "recursive_call"),
        "ThemeOptions::deduce must not recurse into Options: {:?}",
        effects.boundaries
    );
}

/// `Type::from_args()` types the local across files; a non-constructor
/// associated function (`filename`) must not dispatch the type's methods.
#[test]
fn associated_constructor_types_cross_file_receiver() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-assoc-ctor",
        &[
            (
                "src/main.rs",
                "mod fs;\nuse crate::fs::File;\nfn main() {\n    let f = File::from_args();\n    f.wipe();\n    let name = File::filename();\n    name.wipe();\n}\n",
            ),
            (
                "src/fs.rs",
                concat!(
                    "pub struct File;\n",
                    "impl File {\n",
                    "    pub fn from_args() -> File { File }\n",
                    "    pub fn filename() -> String { String::new() }\n",
                    "    pub fn wipe(&self) {\n        std::fs::remove_file(\"/var/wiped\").ok();\n    }\n",
                    "}\n",
                ),
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/wiped").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "src/main.rs"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "from_args-typed receiver reaches wipe: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    // `filename()` is not a constructor: only the from_args path may fire,
    // so a single delete (not a doubled guess through `name`).
    let effects = effects_of(&idx, "src/main.rs")
        .expect("entrypoint indexed")
        .payload
        .into_effects()
        .unwrap();
    let deletes = effects
        .effects
        .iter()
        .filter(|e| e.operation.as_str() == "filesystem.delete")
        .count();
    assert_eq!(
        deletes, 1,
        "filename must not type-as File: {:?}",
        effects.effects
    );
}

fn grep_workspace(grep_root: &str, bin_main: &str, cli_lib: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/core\", \"crates/grep\", \"crates/cli\"]\n".into(),
        ),
        (
            "crates/core/Cargo.toml",
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\n".into(),
        ),
        ("crates/core/src/main.rs", bin_main.into()),
        (
            "crates/grep/Cargo.toml",
            "[package]\nname = \"grep\"\nversion = \"0.1.0\"\n".into(),
        ),
        ("crates/grep/src/lib.rs", grep_root.into()),
        (
            "crates/cli/Cargo.toml",
            "[package]\nname = \"grep-cli\"\nversion = \"0.1.0\"\n".into(),
        ),
        ("crates/cli/src/lib.rs", cli_lib.into()),
    ]
}

fn grep_cross_module(
    composition: &effinterp_repo::Composition,
) -> Vec<&effinterp_repo::ComposedBoundary> {
    composition
        .boundaries
        .iter()
        .filter(|boundary| {
            boundary.reason == "cross_module"
                && (boundary.detail.contains("grep::")
                    || boundary.detail.contains("unresolved on receiver grep::"))
        })
        .collect()
}

/// A crate root `pub extern crate grep_cli as cli` lets a bin call through
/// `grep::cli::hostname` into the aliased workspace crate.
#[test]
fn workspace_crate_root_extern_crate_alias_composes() {
    let mut files = grep_workspace(
        "pub extern crate grep_cli as cli;\n",
        "use grep::cli::hostname;\nfn main() {\n    hostname();\n}\n",
        "mod hostname;\npub use crate::hostname::hostname;\n",
    );
    files.push((
        "crates/cli/src/hostname.rs",
        "pub fn hostname() {\n    std::fs::remove_file(\"/var/hostname.lock\");\n}\n".into(),
    ));
    let owned: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, content)| (*path, content.as_str()))
        .collect();
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-grep-extern-crate-alias",
        &owned,
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &Selector::parse("fs:/var/hostname.lock").unwrap(),
        None,
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "crates/core/src/main.rs"
                    && hit.fact.operation.as_str() == "filesystem.delete"
            }),
        "extern crate alias must compose: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    let composition = idx
        .composition("crates/core/src/main.rs")
        .expect("bin entrypoint indexed");
    assert!(
        grep_cross_module(composition).is_empty(),
        "no grep:: cross_module: {:?}",
        composition.boundaries
    );
}

/// The same alias written as `pub use grep_cli as cli`.
#[test]
fn workspace_crate_root_use_alias_composes() {
    let mut files = grep_workspace(
        "pub use grep_cli as cli;\n",
        "use grep::cli::hostname;\nfn main() {\n    hostname();\n}\n",
        "mod hostname;\npub use crate::hostname::hostname;\n",
    );
    files.push((
        "crates/cli/src/hostname.rs",
        "pub fn hostname() {\n    std::fs::remove_file(\"/var/hostname-use.lock\");\n}\n".into(),
    ));
    let owned: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, content)| (*path, content.as_str()))
        .collect();
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-grep-use-crate-alias",
        &owned,
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &Selector::parse("fs:/var/hostname-use.lock").unwrap(),
        None,
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "crates/core/src/main.rs"
                    && hit.fact.operation.as_str() == "filesystem.delete"
            }),
        "use crate alias must compose: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    let composition = idx
        .composition("crates/core/src/main.rs")
        .expect("bin entrypoint indexed");
    assert!(
        grep_cross_module(composition).is_empty(),
        "no grep:: cross_module: {:?}",
        composition.boundaries
    );
}

/// uv's `use uv::main as uv_main` inside `unsafe` still reaches the lib.
#[test]
fn uv_main_alias_in_unsafe_reaches_lib() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-uv-main-alias",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"uv\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/lib.rs",
                concat!(
                    "pub unsafe fn main<I, T>(_args: I) -> std::process::ExitCode {\n",
                    "    std::fs::remove_file(\"/var/uv.lock\").ok();\n",
                    "    std::process::ExitCode::SUCCESS\n",
                    "}\n",
                ),
            ),
            (
                "src/bin/uv.rs",
                concat!(
                    "#[cfg(windows)]\n",
                    "extern crate uv;\n",
                    "use uv::main as uv_main;\n",
                    "fn main() -> std::process::ExitCode {\n",
                    "    unsafe { uv_main(std::env::args_os()) }\n",
                    "}\n",
                ),
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/uv.lock").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "src/bin/uv.rs"
                    && hit.fact.operation.as_str() == "filesystem.delete"
            }),
        "uv_main alias must compose: matches={:?} entrypoints={:?}",
        report.payload.as_reach().unwrap().matches,
        idx.entrypoints
    );
}

/// An alias whose target crate is not a workspace member stays unresolved.
#[test]
fn absent_crate_alias_stays_cross_module() {
    let files = grep_workspace(
        "#[cfg(feature = \"pcre2\")]\npub extern crate grep_pcre2 as pcre2;\n",
        "use grep::pcre2::compile;\nfn main() {\n    compile();\n}\n",
        "pub fn unused() {}\n",
    );
    let owned: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, content)| (*path, content.as_str()))
        .collect();
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-grep-absent-pcre2-alias",
        &owned,
    );
    let idx = build_index(&root, IndexLimits::default());
    let composition = idx
        .composition("crates/core/src/main.rs")
        .expect("bin entrypoint indexed");
    assert!(
        !composition
            .effects
            .iter()
            .any(|effect| { effect.effect.operation.0 == "filesystem.delete" }),
        "absent crate must not invent an effect: {:?}",
        composition.effects
    );
    assert!(
        composition.boundaries.iter().any(|boundary| {
            boundary.reason == "cross_module" && boundary.detail.contains("grep::")
        }),
        "absent crate alias stays cross_module: {:?}",
        composition.boundaries
    );
}

/// A type reached through the crate-root alias still dispatches its methods.
#[test]
fn workspace_crate_root_alias_typed_receiver_composes() {
    let files = grep_workspace(
        "pub extern crate grep_cli as cli;\n",
        "fn main() {\n    grep::cli::Builder::new().run();\n}\n",
        concat!(
            "pub struct Builder;\n",
            "impl Builder {\n",
            "    pub fn new() -> Self { Builder }\n",
            "    pub fn run(&self) {\n",
            "        std::fs::remove_file(\"/var/builder.lock\").ok();\n",
            "    }\n",
            "}\n",
        ),
    );
    let owned: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, content)| (*path, content.as_str()))
        .collect();
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-grep-alias-typed-receiver",
        &owned,
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &Selector::parse("fs:/var/builder.lock").unwrap(),
        None,
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "crates/core/src/main.rs"
                    && hit.fact.operation.as_str() == "filesystem.delete"
            }),
        "aliased type must compose: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    let composition = idx
        .composition("crates/core/src/main.rs")
        .expect("bin entrypoint indexed");
    assert!(
        grep_cross_module(composition).is_empty(),
        "no grep:: cross_module: {:?}",
        composition.boundaries
    );
    assert!(
        !composition.boundaries.iter().any(|boundary| {
            boundary.reason == "unresolved_call"
                && boundary.detail.contains("unresolved on receiver grep::")
        }),
        "aliased receiver must resolve: {:?}",
        composition.boundaries
    );
}

/// `cli::main!(app)` hands off to `app::main` in a sibling workspace crate.
#[test]
fn main_macro_reaches_workspace_crate_entry() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-main-macro-workspace",
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"app\", \"cli\"]\n"),
            (
                "cli/Cargo.toml",
                "[package]\nname = \"cli\"\nversion = \"0.1.0\"\n",
            ),
            ("cli/src/main.rs", "framework::main!(app);\n"),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            (
                "app/src/lib.rs",
                "pub fn main() {\n    std::fs::remove_file(\"/var/app.lock\");\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/app.lock").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "cli/src/main.rs"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "main! handoff reaches the workspace crate: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

#[test]
fn trait_candidates_require_matching_method_signatures() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nmod wrong;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.send(\"/x\"); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Sink { fn send(&self, path: &str) -> Result<(), ()>; }\n",
            ),
            (
                "src/right.rs",
                "use crate::contract::Sink;\npub struct Right;\nimpl Sink for Right { fn send(&self, path: &str) -> Result<(), ()> { std::fs::remove_file(\"/rust-signature-right\").ok(); Ok(()) } }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::Sink;\npub struct Wrong;\nimpl Sink for Wrong { fn send(&self, path: i32) -> Result<(), ()> { std::fs::remove_file(\"/rust-signature-wrong\").ok(); Ok(()) } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/rust-signature-right"]);
}

#[test]
fn trait_receiver_is_not_resolved_as_an_import() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-receiver-import",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.send(\"/x\"); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Sink { fn send(&self, path: &str); }\n",
            ),
            (
                "src/right.rs",
                "use std::io::{self, Write};\nuse crate::contract::Sink;\npub struct Right;\nimpl Sink for Right { fn send(&self, path: &str) { std::fs::remove_file(\"/rust-receiver-import\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/rust-receiver-import"
            ),
        "signature syntax must not resolve through imports: {:?}",
        effects.boundaries
    );
}

#[test]
fn generic_trait_candidates_apply_implementation_type_arguments() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-generic-trait-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nmod wrong;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink<String> = external(); sink.send(external()); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Sink<T> { fn send(&self, value: T); }\n",
            ),
            (
                "src/right.rs",
                "use crate::contract::Sink;\npub struct Right;\nimpl Sink<String> for Right { fn send(&self, value: String) { std::fs::remove_file(\"/rust-generic-trait-right\").ok(); } }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::Sink;\npub struct Wrong;\nimpl Sink<String> for Wrong { fn send(&self, value: u32) { std::fs::remove_file(\"/rust-generic-trait-wrong\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/rust-generic-trait-right"]);
}

#[test]
fn impl_trait_candidates_require_matching_bounds() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-impl-trait-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nmod wrong;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.send(external()); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Sink { fn send(&self, value: impl AsRef<str>); }\n",
            ),
            (
                "src/right.rs",
                "use crate::contract::Sink;\npub struct Right;\nimpl Sink for Right { fn send(&self, value: impl AsRef<str>) { std::fs::remove_file(\"/rust-impl-trait-right\").ok(); } }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::Sink;\npub struct Wrong;\nimpl Sink for Wrong { fn send(&self, value: impl Into<u32>) { std::fs::remove_file(\"/rust-impl-trait-wrong\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/rust-impl-trait-right"]);
}

#[test]
fn trait_candidates_distinguish_function_pointer_signatures() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-function-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nmod wrong;\nuse crate::contract::Runner;\nfn main() { let runner: &dyn Runner = external(); runner.run(external()); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Runner { fn run(&self, callback: fn(u32)); }\n",
            ),
            (
                "src/right.rs",
                "use crate::contract::Runner;\npub struct Right;\nimpl Runner for Right { fn run(&self, callback: fn(u32)) { std::fs::remove_file(\"/rust-function-signature-right\").ok(); } }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::Runner;\npub struct Wrong;\nimpl Runner for Wrong { fn run(&self, callback: fn(String, i64) -> bool) { std::fs::remove_file(\"/rust-function-signature-wrong\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/rust-function-signature-right"]);
}

#[test]
fn trait_candidates_preserve_structural_generic_arguments() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-structural-generics",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nmod wrong;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.associated(external()); sink.const_generic(external()); sink.callable(external()); }\n",
            ),
            (
                "src/contract.rs",
                "pub struct Buf<const N: usize>;\npub trait Sink { fn associated(&self, value: Box<dyn Iterator<Item = u8>>); fn const_generic(&self, value: Buf<4>); fn callable(&self, value: Box<dyn Fn(u32)>); }\n",
            ),
            (
                "src/right.rs",
                "use crate::contract::{Buf, Sink};\npub struct Right;\nimpl Sink for Right { fn associated(&self, value: Box<dyn Iterator<Item = u8>>) { std::fs::remove_file(\"/rust-structural-associated\").ok(); } fn const_generic(&self, value: Buf<4>) { std::fs::remove_file(\"/rust-structural-const\").ok(); } fn callable(&self, value: Box<dyn Fn(u32)>) { std::fs::remove_file(\"/rust-structural-callable\").ok(); } }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::{Buf, Sink};\npub struct Wrong;\nimpl Sink for Wrong { fn associated(&self, value: Box<dyn Iterator<Item = String>>) { std::fs::remove_file(\"/rust-structural-wrong-associated\").ok(); } fn const_generic(&self, value: Buf<8>) { std::fs::remove_file(\"/rust-structural-wrong-const\").ok(); } fn callable(&self, value: Box<dyn Fn(String) -> bool>) { std::fs::remove_file(\"/rust-structural-wrong-callable\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let mut deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    deletes.sort_unstable();
    assert_eq!(
        deletes,
        [
            "fs:/rust-structural-associated",
            "fs:/rust-structural-callable",
            "fs:/rust-structural-const"
        ]
    );
}

#[test]
fn trait_candidates_normalize_lifetime_bounds() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-lifetime-bound",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod right;\nmod wrong;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.send(); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Sink { fn send(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>; }\n",
            ),
            (
                "src/right.rs",
                "use crate::contract::Sink;\npub struct Right;\nimpl Sink for Right { fn send(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> { std::fs::remove_file(\"/rust-lifetime-bound-right\").ok(); Ok(()) } }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::Sink;\npub struct Wrong;\nimpl Sink for Wrong { fn send(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { std::fs::remove_file(\"/rust-lifetime-bound-wrong\").ok(); Ok(()) } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/rust-lifetime-bound-right"]);
}

#[test]
fn unsupported_trait_signature_types_do_not_admit_candidates() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-unsupported-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod wrong;\nuse crate::contract::Runner;\nfn main() { let runner: &dyn Runner = external(); runner.run(external()); }\n",
            ),
            (
                "src/contract.rs",
                "pub trait Runner { fn run(&self, value: contract_type!()); }\n",
            ),
            (
                "src/wrong.rs",
                "use crate::contract::Runner;\npub struct Wrong;\nimpl Runner for Wrong { fn run(&self, value: wrong_type!()) { std::fs::remove_file(\"/rust-unsupported-signature-wrong\").ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/rust-unsupported-signature-wrong"
            ),
        "unsupported signature forms must not compare as exact: {:?}",
        effects.effects
    );
}

#[test]
fn trait_self_results_match_the_implementation_receiver() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-self-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod disk;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.purge(std::path::Path::new(\"/x\")); }\n",
            ),
            (
                "src/contract.rs",
                "use std::path::Path;\npub trait Sink { fn purge(&self, root: &Path) -> Self; }\n",
            ),
            (
                "src/disk.rs",
                "use crate::contract::Sink;\npub struct Disk;\nimpl Sink for Disk { fn purge(&self, root: &std::path::Path) -> Disk { std::fs::remove_file(\"/rust-trait-self\").ok(); Disk } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/rust-trait-self"
            ),
        "Self and the implementation receiver are the same signature type: {:?}",
        effects.boundaries
    );
}

#[test]
fn trait_concrete_self_types_match_the_implementation_receiver() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-concrete-self-signature",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod widget;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.run(external()); sink.make(); }\n",
            ),
            (
                "src/contract.rs",
                "use crate::widget::Widget;\npub trait Sink { fn run(&self, other: &Widget); fn make(&self) -> Widget; }\n",
            ),
            (
                "src/widget.rs",
                "use crate::contract::Sink;\npub struct Widget;\nimpl Sink for Widget { fn run(&self, other: &Widget) { std::fs::remove_file(\"/rust-trait-self-param\").ok(); } fn make(&self) -> Widget { std::fs::remove_file(\"/rust-trait-self-result\").ok(); Widget } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(
        deletes,
        ["fs:/rust-trait-self-param", "fs:/rust-trait-self-result"],
        "the implementation receiver and its concrete trait spelling are identical: {:?}",
        effects.boundaries
    );
}

#[test]
fn trait_local_signature_types_match_imported_implementation_types() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-local-signature-types",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod disk;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.run(external()); }\n",
            ),
            (
                "src/contract.rs",
                "pub struct Job;\npub type Outcome = Result<(), ()>;\npub trait Sink { fn run(&self, job: &Job) -> Outcome; }\n",
            ),
            (
                "src/disk.rs",
                "use crate::contract::{Job, Outcome, Sink};\npub struct Disk;\nimpl Sink for Disk { fn run(&self, job: &Job) -> Outcome { std::fs::remove_file(\"/rust-trait-local-type\").ok(); Ok(()) } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/rust-trait-local-type"
            ),
        "local and imported spellings must identify the same signature types: {:?}",
        effects.boundaries
    );
}

#[test]
fn trait_signature_lifetime_names_do_not_change_identity() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-trait-signature-lifetimes",
        &[
            (
                "src/main.rs",
                "mod contract;\nmod disk;\nuse crate::contract::Sink;\nfn main() { let sink: &dyn Sink = external(); sink.purge(external()); }\n",
            ),
            (
                "src/contract.rs",
                "use std::borrow::Cow;\npub trait Sink { fn purge(&self, path: Cow<'_, str>); }\n",
            ),
            (
                "src/disk.rs",
                "use std::borrow::Cow;\nuse crate::contract::Sink;\npub struct Disk;\nimpl Sink for Disk { fn purge<'a>(&self, path: Cow<'a, str>) { std::fs::remove_file(path.as_ref()).ok(); } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "equivalent lifetime spellings must preserve the trait candidate: {:?}",
        effects.boundaries
    );
}

#[test]
fn awaited_and_called_work_crosses_modules_without_unused_futures_or_closures() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-async-closure",
        &[
            (
                "src/main.rs",
                "mod worker;\nasync fn main() {\n    worker::unused_future();\n    let unused_stored = worker::unused_stored();\n    worker::used_future().await;\n    let stored = worker::stored_future();\n    stored.await;\n    tokio::spawn(worker::spawned_future());\n    let spawned_stored = worker::spawned_stored();\n    tokio::spawn(spawned_stored);\n    futures::executor::block_on(worker::blocked_future());\n    let pending = worker::make();\n    let worker = pending.await.unwrap();\n    worker.run();\n    let unused = || worker::unused_closure();\n    let called = || worker::used_closure();\n    called();\n}\n",
            ),
            (
                "src/worker.rs",
                "pub async fn unused_future() { std::fs::remove_file(\"/unused-future\"); }\npub async fn unused_stored() { std::fs::remove_file(\"/unused-stored\"); }\npub async fn used_future() { std::fs::remove_file(\"/used-future\"); }\npub async fn stored_future() { std::fs::remove_file(\"/stored-future\"); }\npub async fn spawned_future() { std::fs::remove_file(\"/spawned-future\"); }\npub async fn spawned_stored() { std::fs::remove_file(\"/spawned-stored\"); }\npub async fn blocked_future() { std::fs::remove_file(\"/blocked-future\"); }\npub struct Worker;\npub async fn make() -> Result<Worker, ()> { Ok(Worker) }\nimpl Worker { pub fn run(&self) { std::fs::remove_file(\"/worker-result\"); } }\npub fn unused_closure() { std::fs::remove_file(\"/unused-closure\"); }\npub fn used_closure() { std::fs::remove_file(\"/used-closure\"); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let mut deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    deletes.sort();
    assert_eq!(
        deletes,
        [
            "fs:/blocked-future",
            "fs:/spawned-future",
            "fs:/spawned-stored",
            "fs:/stored-future",
            "fs:/used-closure",
            "fs:/used-future",
            "fs:/worker-result"
        ]
    );
}

#[test]
fn stored_future_arguments_execute_across_modules() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-eager-future-argument",
        &[
            (
                "src/main.rs",
                "mod work;\nasync fn hold(_: ()) {}\nfn main() { let _future = hold(work::wipe()); }\n",
            ),
            (
                "src/work.rs",
                "pub fn wipe() { std::fs::remove_file(\"/eager-argument\"); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/eager-argument"
        }),
        "future call arguments execute before polling: {:?}",
        effects.effects
    );
}

#[test]
fn indirect_closure_calls_remain_explicit_boundaries() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-indirect-closure",
        &[(
            "src/main.rs",
            "struct Handler { call: fn() }\nfn main() {\n    let handler = Handler { call: || std::fs::remove_file(\"/struct-closure\") };\n    (handler.call)();\n    let tuple = (\"unused\", || std::fs::remove_file(\"/tuple-closure\"));\n    (tuple.1)();\n}\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects.boundaries.iter().any(|boundary| {
            boundary.reason == "unresolved_call"
                && boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("indirect callable expression"))
        }),
        "indirect closure calls must not claim full coverage: {:?}",
        effects.boundaries
    );
}

#[test]
fn unmodeled_cross_module_future_driver_remains_loud() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "rust-unmodeled-future-driver",
        &[
            (
                "src/main.rs",
                "mod worker;\nfn main() {\n    let rt = tokio::runtime::Runtime::new().unwrap();\n    rt.block_on(worker::wipe());\n}\n",
            ),
            (
                "src/worker.rs",
                "pub async fn wipe() { std::fs::remove_file(\"/runtime\"); }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "src/main.rs")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects.boundaries.iter().any(|boundary| {
            boundary.reason == "unpolled_async"
                && boundary.detail.as_deref().is_some_and(|detail| {
                    detail.contains("wipe") && detail.contains("not known to be polled")
                })
        }),
        "unmodeled cross-module future drivers must remain explicit: {:?}",
        effects.boundaries
    );
    assert!(
        effects
            .coverage
            .values()
            .any(|claim| claim.level == effinterp_proto::CoverageLevel::Partial),
        "an unmodeled future driver degrades coverage: {:?}",
        effects.coverage
    );
}
