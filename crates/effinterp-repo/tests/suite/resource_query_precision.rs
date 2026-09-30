#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_proto::{
    CausalAssurance, CausalReason, OccurrenceKind, ResourceExpr, ResourceIdentity,
};
use effinterp_repo::{IndexLimits, Selector, build_index, effects_of, reach};

use crate::{causal_path, plan_causality, typed_selector};

fn repo(tag: &str, source: &str) -> PathBuf {
    repo_files(tag, &[("run.sh", source)])
}

fn repo_files(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(tag);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for (name, source) in files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    root
}

fn index(tag: &str, source: &str) -> effinterp_repo::RepoIndex {
    build_index(&repo(tag, source), IndexLimits::default())
}

struct UnknownEffect<'a> {
    fact: &'a effinterp_proto::EffectFact,
    matched: &'a effinterp_proto::Match,
}
fn unknown_effects(
    report: &effinterp_proto::RepoQueryEnvelope,
) -> impl Iterator<Item = UnknownEffect<'_>> {
    report
        .payload
        .as_reach()
        .unwrap()
        .indeterminate
        .iter()
        .filter_map(|row| match row {
            effinterp_proto::Indeterminate::Effect { fact, matched, .. } => {
                Some(UnknownEffect { fact, matched })
            }
            _ => None,
        })
}

#[test]
fn typed_identity_queries_preserve_unknown_process_cwd() {
    let idx = index(
        "resource-roundtrip",
        "#!/bin/sh\nrm /srv/./data\nprintf '%s' value\ndocker run --name worker -v /host/data:/data example/worker:v1\npsql -h DB.EXAMPLE -d app -c 'UPDATE audit.events SET seen=true'\n",
    );
    let forward = effects_of(&idx, "run.sh").unwrap();
    for operation in [
        "filesystem.delete",
        "process.exec",
        "container.run",
        "database.write",
    ] {
        let row = forward
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .find(|row| row.operation.0 == operation)
            .unwrap_or_else(|| panic!("missing {operation}"));
        let selector = typed_selector(&row.resource);
        let report = reach(&idx, &Selector::parse(&selector).unwrap(), Some(operation));
        if operation == "process.exec" {
            assert!(unknown_effects(&report).any(|hit| hit.fact.resource == row.resource));
            continue;
        }
        let expected = true;
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|hit| {
                    hit.fact.entrypoint == "run.sh"
                        && hit.fact.operation.0 == operation
                        && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
                            == expected
                        && hit.fact.resource == row.resource
                }),
            "{operation} failed round trip with {selector}"
        );
    }
}

#[test]
fn aliases_deduplicate_but_disambiguating_fields_do_not() {
    let idx = index(
        "resource-aliases",
        "#!/bin/sh\nrm /tmp/a/../x\nrm /tmp/x\ndocker run alpine\npodman run alpine\npsql -h one -d app -c 'UPDATE public.users SET x=1'\npsql -h two -d app -c 'UPDATE public.users SET x=1'\n",
    );
    let forward = effects_of(&idx, "run.sh").unwrap();
    assert_eq!(
        forward
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .filter(|row| {
                row.operation.0 == "filesystem.delete"
                    && matches!(&row.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "/tmp/x")
            })
            .count(),
        1
    );

    let processes: Vec<_> = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|row| {
            matches!(&row.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "rm")
        })
        .collect();
    assert_eq!(processes.len(), 2);
    assert_ne!(processes[0].resource, processes[1].resource);

    let containers: Vec<_> = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter_map(|row| match &row.resource {
            ResourceExpr::Concrete {
                identity: identity @ ResourceIdentity::Container { .. },
            } if row.operation.0 == "container.run" => Some(identity),
            _ => None,
        })
        .collect();
    assert_eq!(containers.len(), 2);
    assert_ne!(containers[0], containers[1]);

    let tables: Vec<_> = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter_map(|row| match &row.resource {
            ResourceExpr::Concrete {
                identity: identity @ ResourceIdentity::DatabaseTable { .. },
            } if row.operation.0 == "database.write" => Some(identity),
            _ => None,
        })
        .collect();
    assert_eq!(tables.len(), 2);
    assert_ne!(tables[0], tables[1]);
}

#[test]
fn patterns_and_partial_human_selectors_return_membership_proofs() {
    let idx = index(
        "resource-possible",
        "#!/bin/sh\nrm /tmp/build-*\npsql -h db -d app -c 'UPDATE public.users SET x=1'\n",
    );
    let pattern = reach(&idx, &Selector::parse("fs:/tmp/build-1").unwrap(), None);
    assert!(
        pattern
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
    );

    let prefix = reach(&idx, &Selector::parse("fs:/tmp").unwrap(), None);
    assert!(
        prefix
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                effinterp_proto::display_resource(&hit.fact.resource) == "fs:/tmp/build-*"
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
            })
    );

    let exact = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/tmp/build-1".to_string(),
        },
    };
    let selector = typed_selector(&exact);
    let typed_pattern = reach(&idx, &Selector::parse(&selector).unwrap(), None);
    assert!(
        typed_pattern
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                effinterp_proto::display_resource(&hit.fact.resource) == "fs:/tmp/build-*"
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
            })
    );

    let partial = reach(&idx, &Selector::parse("db:public.users").unwrap(), None);
    assert!(
        partial
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.operation.0 == "database.write")
    );
}

#[test]
fn environment_and_git_queries_distinguish_exact_from_repository_scope() {
    let idx = index(
        "resource-environment-git",
        "#!/bin/sh\nprintf '%s' \"$HOME\"\ngit -C /repo restore src/lib.rs\n",
    );
    let forward = effects_of(&idx, "run.sh").unwrap();
    let environment = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "environment.read")
        .unwrap();
    assert!(matches!(&environment.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::EnvironmentVariable { name }
    } if name == "HOME"));
    let human = reach(
        &idx,
        &Selector::parse("env:HOME").unwrap(),
        Some("environment.read"),
    );
    assert!(human.payload.as_reach().unwrap().matches.iter().any(|hit| {
        hit.fact.resource == environment.resource
            && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
    }));
    let exact = typed_selector(&environment.resource);
    let exact = reach(
        &idx,
        &Selector::parse(&exact).unwrap(),
        Some("environment.read"),
    );
    assert!(exact.payload.as_reach().unwrap().matches.iter().any(|hit| {
        hit.fact.resource == environment.resource
            && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
    }));

    let git = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard")
        .unwrap();
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec: Some(_),
            },
    } = &git.resource
    else {
        panic!("expected path-scoped Git identity: {:?}", git.resource)
    };
    let repository = ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: worktree.clone(),
            git_dir: git_dir.clone(),
            pathspec: None,
        },
    };
    let repository = effinterp_proto::display_resource(&repository);
    let repository = reach(
        &idx,
        &Selector::parse(&repository).unwrap(),
        Some("git.worktree_discard"),
    );
    assert!(
        repository
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.resource == git.resource
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
            }),
        "repository query result: {:?}; resource: {:?}",
        repository.payload.as_reach().unwrap().matches,
        git.resource
    );
    let exact = typed_selector(&git.resource);
    let exact = reach(
        &idx,
        &Selector::parse(&exact).unwrap(),
        Some("git.worktree_discard"),
    );
    assert!(exact.payload.as_reach().unwrap().matches.iter().any(|hit| {
        hit.fact.resource == git.resource
            && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
    }));
}

#[test]
fn symbolic_git_scope_stays_indeterminate_through_a_typed_selector() {
    let idx = index(
        "resource-symbolic-git",
        "#!/bin/sh\ngit -C \"$ROOT\" restore \"$PATHSPEC\"\n",
    );
    let forward = effects_of(&idx, "run.sh").unwrap();
    let git = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard")
        .unwrap();
    assert!(matches!(&git.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: Some(worktree),
            pathspec: Some(pathspec),
            ..
        }
    } if matches!(worktree.as_ref(), ResourceExpr::Environment { name } if name == "ROOT")
        && matches!(pathspec.as_ref(), ResourceExpr::Environment { name } if name == "PATHSPEC")));

    let human = effinterp_proto::display_resource(&git.resource);
    let human = reach(
        &idx,
        &Selector::parse(&human).unwrap(),
        Some("git.worktree_discard"),
    );
    assert!(
        unknown_effects(&human).any(|hit| {
            hit.fact.resource == git.resource
                && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. })
        }),
        "human query result: {:?}; resource: {:?}",
        human.payload.as_reach().unwrap().matches,
        git.resource
    );
    let exact = typed_selector(&git.resource);
    let exact = reach(
        &idx,
        &Selector::parse(&exact).unwrap(),
        Some("git.worktree_discard"),
    );
    assert!(unknown_effects(&exact).any(|hit| {
        hit.fact.resource == git.resource
            && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. })
    }));
}

#[test]
fn network_queries_discriminate_every_known_endpoint_field() {
    let idx = index(
        "resource-network-scope",
        "#!/bin/sh\ncurl https://example.com:8443/a\ncurl http://example.com:8443/b\n",
    );
    let host = reach(
        &idx,
        &Selector::parse("net:example.com").unwrap(),
        Some("network.request"),
    );
    assert!(host.payload.as_reach().unwrap().matches.len() >= 2);
    assert!(
        host.payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
    );

    let exact_human = reach(
        &idx,
        &Selector::parse("net:https://example.com:8443/a").unwrap(),
        Some("network.request"),
    );
    assert!(
        exact_human
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
                    && matches!(&hit.fact.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    scheme: Some(scheme),
                    path: Some(path),
                    ..
                }
            } if scheme == "https" && path == "/a")
            })
    );
    assert!(
        !exact_human
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                matches!(&hit.fact.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                scheme: Some(scheme),
                path: Some(path),
                ..
            }
        } if scheme == "http" || path == "/b")
            })
    );
}

#[test]
fn labelled_database_queries_do_not_flatten_distinct_scope_positions() {
    let idx = index(
        "resource-database-scope",
        "#!/bin/sh\npsql -h one -d app -c 'UPDATE public.users SET x=1'\npsql -h two -d app -c 'UPDATE public.users SET x=1'\n",
    );
    let forward = effects_of(&idx, "run.sh").unwrap();
    let first = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| {
            matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseTable { server: Some(server), .. }
        } if server == "one")
        })
        .unwrap();
    let rendered = effinterp_proto::display_resource(&first.resource);
    let labelled = reach(
        &idx,
        &Selector::parse(&rendered).unwrap(),
        Some("database.write"),
    );
    assert!(
        labelled
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.resource == first.resource)
    );
    assert!(!labelled.payload.as_reach().unwrap().matches.iter().any(
        |hit| matches!(&hit.fact.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseTable { server: Some(server), .. }
        } if server == "two")
    ));

    let short = reach(
        &idx,
        &Selector::parse("db:public.users").unwrap(),
        Some("database.write"),
    );
    assert!(short.payload.as_reach().unwrap().matches.len() >= 2);
    assert!(
        short
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
    );
}

#[test]
fn named_container_keeps_and_matches_its_image_identity() {
    let idx = index(
        "resource-container-name-image",
        "#!/bin/sh\ndocker run --name web nginx:1.25\ndocker run redis:7\n",
    );
    let forward = effects_of(&idx, "run.sh").unwrap();
    let named = forward
        .payload.as_effects().unwrap().effects
        .iter()
        .find(|row| {
            row.operation.0 == "container.run"
                && matches!(&row.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container { name: Some(name), image: Some(image), .. }
                } if name == "web" && image == "nginx:1.25")
        })
        .unwrap();
    assert_eq!(
        effinterp_proto::display_resource(&named.resource),
        "container:docker:web [image=nginx:1.25]"
    );

    let report = reach(
        &idx,
        &Selector::parse("container:docker:web").unwrap(),
        Some("container.run"),
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "run.sh"
                    && hit.fact.resource == named.resource
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
            })
    );
    assert!(
        !report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                matches!(&hit.fact.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Container { image: Some(image), .. }
        } if image == "redis:7")
            })
    );

    let copied_display = reach(
        &idx,
        &Selector::parse(&typed_selector(&named.resource)).unwrap(),
        Some("container.run"),
    );
    assert!(
        copied_display
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "run.sh"
                    && hit.fact.resource == named.resource
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
            })
    );
}

#[test]
fn executable_selector_matches_process_with_arguments() {
    let idx = index("resource-process-display", "#!/bin/sh\nrm -rf /tmp/x\n");
    let forward = effects_of(&idx, "run.sh").unwrap();
    let row = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|row| {
            row.operation.0 == "process.exec"
                && matches!(&row.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. }
                } if executable == "rm")
        })
        .unwrap();
    let report = reach(
        &idx,
        &Selector::parse("proc:rm").unwrap(),
        Some("process.exec"),
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "run.sh"
                    && hit.fact.resource == row.resource
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
            })
    );
}

#[test]
fn unknown_external_surfaces_cannot_produce_a_precise_network_negative() {
    for (tag, source) in [
        (
            "resource-python-exec-opaque",
            "#!/usr/bin/env python\nimport pty\npty.spawn(['curl', 'https://example.com'])\n",
        ),
        (
            "resource-python-handler-opaque",
            "#!/usr/bin/env python\nimport logging.handlers\nlogging.handlers.HTTPHandler('example.com', '/log')\n",
        ),
    ] {
        let root = repo_files(tag, &[("app.py", source)]);
        let idx = build_index(&root, IndexLimits::default());
        let report = reach(&idx, &Selector::parse("net:example.com").unwrap(), None);
        assert!(
            report.payload.as_reach().unwrap().matches.is_empty(),
            "{source}"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .indeterminate
                .iter()
                .filter_map(|row| match row {
                    effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
                    _ => None,
                })
                .any(|row| {
                    row.entrypoint == "app.py"
                        && row.domain == "network"
                        && row.boundary_reason == "external_unmodeled"
                }),
            "external uncertainty must prevent a precise negative: {:?}",
            report.payload.as_reach().unwrap().indeterminate
        );
    }
}

#[test]
fn unix_net_listen_reports_its_filesystem_socket() {
    let root = repo_files(
        "resource-go-listen-opaque",
        &[(
            "main.go",
            "package main\nimport \"net\"\nfunc main() { net.Listen(\"unix\", \"/tmp/probe.sock\") }\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let effects = effects_of(&idx, "main.go").unwrap();
    assert!(
        effects
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "network.listen"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::NetworkEndpoint {
                                host,
                                scheme: Some(scheme),
                                ..
                            }
                        } if host == "/tmp/probe.sock" && scheme == "unix"
                    )
            })
    );
    assert!(
        effects
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.create"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        } if path == "/tmp/probe.sock"
                    )
            })
    );
    let report = reach(&idx, &Selector::parse("fs:/tmp/probe.sock").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|row| row.fact.entrypoint == "main.go")
    );
}

#[test]
fn reverse_filesystem_query_matches_python_and_shell_environment_joins() {
    let idx = build_index(
        &repo_files(
            "python-environment-join",
            &[
                (
                    "clean.py",
                    "#!/usr/bin/env python3\nimport os\nos.remove(os.environ['HOME'] + '/.cache/x')\n",
                ),
                ("clean.sh", "#!/bin/sh\nrm -rf \"$HOME\"/.cache/x\n"),
            ],
        ),
        IndexLimits::default(),
    );
    let report = reach(
        &idx,
        &Selector::parse("fs:$HOME/*").unwrap(),
        Some("filesystem.delete"),
    );
    for entrypoint in ["clean.py", "clean.sh"] {
        assert!(unknown_effects(&report).any(|hit| {
            hit.fact.entrypoint == entrypoint
                && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. })
        }));
    }
}

#[test]
fn cross_file_path_is_canonical_and_round_trips_exactly() {
    let root = repo_files(
        "resource-cross-file-path",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helper import load\nload('/srv/data')\n",
            ),
            (
                "helper.py",
                "import os\ndef load(root):\n    open(os.path.join(root, 'notes.txt'))\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let forward = effects_of(&idx, "app.py").unwrap();
    let row = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|row| row.operation.0 == "filesystem.read")
        .unwrap();
    assert_eq!(
        row.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/srv/data/notes.txt".to_string(),
            },
        }
    );
    assert_eq!(
        effinterp_proto::display_resource(&row.resource),
        "fs:/srv/data/notes.txt"
    );

    let selector = typed_selector(&row.resource);
    let reverse = reach(
        &idx,
        &Selector::parse(&selector).unwrap(),
        Some("filesystem.read"),
    );
    assert!(
        reverse
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "app.py"
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
                    && hit.fact.resource == row.resource
            })
    );
}

#[test]
fn cross_file_process_argv_stays_generic_and_round_trips_exactly() {
    let root = repo_files(
        "resource-cross-file-process",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom wrapper import fetch\nfetch('https://example.com/a')\n",
            ),
            (
                "wrapper.py",
                "from worker import run\ndef fetch(url):\n    run(url)\n",
            ),
            (
                "worker.py",
                "import subprocess\ndef run(url):\n    subprocess.run(['curl', '-o', '/tmp/out', url])\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let forward = effects_of(&idx, "app.py").unwrap();
    let row = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|row| {
            row.operation.0 == "process.exec"
                && matches!(&row.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. }
                } if executable == "curl")
        })
        .unwrap();
    assert!(matches!(&row.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::Process { argv, .. }
    } if matches!(argv.as_slice(), [
        ResourceExpr::Literal { value: output_flag },
        ResourceExpr::Literal { value: output },
        ResourceExpr::Literal { value: url },
    ] if output_flag == "-o"
        && output == "/tmp/out"
        && url == "https://example.com/a")));
    assert!(
        forward
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == "uncomposed_subprocess" })
    );

    let selector = typed_selector(&row.resource);
    let reverse = reach(
        &idx,
        &Selector::parse(&selector).unwrap(),
        Some("process.exec"),
    );
    assert!(
        reverse
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| {
                hit.fact.entrypoint == "app.py"
                    && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
                    && hit.fact.resource == row.resource
            })
    );
}

#[test]
fn rust_pager_process_identity_and_argument_order_round_trip() {
    let root = repo_files(
        "resource-rust-pager-process",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"pager-query\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/main.rs",
                r#"
mod binary;
mod pager;
use std::process::Command;
fn main() {
    let pager = pager::get_pager().unwrap();
    let resolved = binary::resolve_binary(&pager.bin).unwrap();
    let mut command = Command::new(resolved);
    command.args(pager.args);
    command.status();
}
"#,
            ),
            (
                "src/pager.rs",
                r#"
pub struct Pager { pub bin: String, pub args: Vec<String> }
pub fn get_pager() -> Result<Pager, ()> {
    Ok(Pager { bin: "less".to_string(), args: vec!["-R".to_string(), "-F".to_string()] })
}
"#,
            ),
            (
                "src/binary.rs",
                "pub fn resolve_binary(bin: &str) -> Result<String, ()> { Ok(bin.to_owned()) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let process = |argv: [&str; 2]| ResourceExpr::Concrete {
        identity: ResourceIdentity::Process {
            executable: "less".to_string(),
            path: None,
            argv: argv
                .into_iter()
                .map(|value| ResourceExpr::Literal {
                    value: value.to_string(),
                })
                .collect(),
            cwd: None,
        },
    };
    let selector = typed_selector(&process(["-R", "-F"]));
    let reverse = reach(
        &index,
        &Selector::parse(&selector).unwrap(),
        Some("process.exec"),
    );
    assert!(
        reverse
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| { serde_json::to_value(hit).unwrap()["match"]["kind"] == "satisfied" })
    );

    let selector = typed_selector(&process(["-F", "-R"]));
    let reverse = reach(
        &index,
        &Selector::parse(&selector).unwrap(),
        Some("process.exec"),
    );
    assert!(
        !reverse
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| { serde_json::to_value(hit).unwrap()["match"]["kind"] == "satisfied" })
    );
}

#[test]
fn display_dedup_does_not_erase_resource_occurrences() {
    for (source, operation) in [
        (
            "#!/bin/sh\nrm /tmp/same\nrm /tmp/same\n",
            "filesystem.delete",
        ),
        (
            "#!/bin/sh\nkafka-console-producer --topic orders\nkafka-console-producer --topic orders\n",
            "messaging.publish",
        ),
        (
            "#!/bin/sh\nkafka-console-producer --topic orders\nkafka-console-producer --topic orders\n",
            "network.connect",
        ),
    ] {
        let idx = index("resource-occurrence-identity", source);
        let display = effects_of(&idx, "run.sh").unwrap();
        assert_eq!(
            display
                .payload
                .as_effects()
                .unwrap()
                .effects
                .iter()
                .filter(|effect| effect.operation.as_str() == operation)
                .count(),
            1
        );

        let graph = plan_causality(&idx, "run.sh").unwrap();
        let occurrences: Vec<_> = graph
            .nodes
            .iter()
            .filter(|node| {
                matches!(
                    &node.occurrence,
                    OccurrenceKind::ResourceInteraction { operation: actual, .. }
                        if actual.0 == operation
                )
            })
            .collect();
        assert_eq!(occurrences.len(), 2);
        assert_ne!(occurrences[0].id, occurrences[1].id);
        if operation == "filesystem.delete" {
            assert!(graph.edges.iter().any(|edge| {
                edge.reason == CausalReason::ResourceTransition
                    && edge.from == occurrences[0].id
                    && edge.to == occurrences[1].id
            }));
        }
    }
}

#[test]
fn a_piped_read_reaches_the_upload_through_the_causal_graph() {
    let idx = index(
        "resource-causal-path",
        "#!/bin/sh\ncat /srv/input | curl --data-binary @- https://example.com/upload\n",
    );
    let graph = plan_causality(&idx, "run.sh").unwrap();
    let resource = |operation: &str| {
        graph
            .nodes
            .iter()
            .find_map(|node| match &node.occurrence {
                OccurrenceKind::ResourceInteraction { operation: op, .. } if op.0 == operation => {
                    Some(node.id.clone())
                }
                _ => None,
            })
            .unwrap()
    };
    let read = resource("filesystem.read");
    let upload = resource("network.upload");
    assert!(graph.edges.iter().any(|edge| {
        edge.from == read
            && edge.reason == CausalReason::ValueDependency
            && edge.assurance == CausalAssurance::Exact
    }));
    let path = causal_path(graph, &read, &upload).unwrap();
    assert_eq!(path.first(), Some(&read));
    assert_eq!(path.last(), Some(&upload));
    assert!(path.len() >= 4);
    assert!(causal_path(graph, &upload, &read).is_none());
}

#[test]
fn cross_file_composition_retains_equal_effects_from_distinct_calls() {
    let root = repo_files(
        "resource-composed-occurrences",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helper import wipe\nwipe('/tmp/same')\nwipe('/tmp/same')\n",
            ),
            (
                "helper.py",
                "import os\ndef wipe(path):\n    os.remove(path)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let composition = idx.composition("app.py").unwrap();
    let occurrences: Vec<_> = composition
        .occurrence_effects
        .iter()
        .filter(|occurrence| {
            let effect = &composition.effects[occurrence.effect].effect;
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/tmp/same")
        })
        .collect();
    assert_eq!(occurrences.len(), 2);
}

#[test]
fn unknown_process_argv_does_not_alias_a_literal_question_mark() {
    let root = repo_files(
        "resource-process-unknown",
        &[
            (
                "app_a.py",
                "#!/usr/bin/env python\nimport os\nimport subprocess\nsubprocess.run(['rm', os.environ['TARGET']])\n",
            ),
            (
                "app_b.py",
                "#!/usr/bin/env python\nimport subprocess\nsubprocess.run(['rm', '?'])\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let unknown = effects_of(&idx, "app_a.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects
        .into_iter()
        .find(|row| row.operation.0 == "process.exec")
        .unwrap();
    let literal = effects_of(&idx, "app_b.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects
        .into_iter()
        .find(|row| row.operation.0 == "process.exec")
        .unwrap();
    assert!(matches!(&unknown.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::Process { argv, .. }
    } if matches!(argv.as_slice(), [ResourceExpr::Unresolved { family }]
        if family.0 == "process")));
    assert!(matches!(&literal.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::Process { argv, .. }
    } if matches!(argv.as_slice(), [ResourceExpr::Literal { value }]
        if value == "?")));
    assert_ne!(unknown.resource, literal.resource);

    let selector = typed_selector(&literal.resource);
    let report = reach(
        &idx,
        &Selector::parse(&selector).unwrap(),
        Some("process.exec"),
    );
    assert!(unknown_effects(&report).any(|hit| {
        hit.fact.entrypoint == "app_b.py"
            && hit.fact.resource == literal.resource
            && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. })
    }));
    assert!(
        !report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "app_a.py"
                && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
    );
}

#[test]
fn filesystem_glob_queries_respect_segments_and_keep_exhaustion_uncertain() {
    for (case, source, target, excluded) in [
        (
            "parent-prefix",
            "cd /srv/app; cat ../*.rs",
            "/srv/a.rs",
            "/srv/app/a.rs",
        ),
        (
            "absolute-parent-prefix",
            "cat /srv/../data/*.rs",
            "/data/a.rs",
            "/srv/data/a.rs",
        ),
        (
            "dot-prefix",
            "cd /srv/app; cat ./x/*.rs",
            "/srv/app/x/a.rs",
            "/srv/app/x/a.txt",
        ),
        (
            "empty-segments",
            "cd /srv/app; cat x//./y/*.rs",
            "/srv/app/x/y/a.rs",
            "/srv/app/x/a.rs",
        ),
        (
            r#"all-at"#,
            r#"set -- '/tmp/[ab]'; cat $@/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"quoted-all-at"#,
            r#"set -- '/tmp/[ab]'; cat "$@"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"lone-all-at"#,
            r#"set -- '/tmp/[ab]/*.rs'; cat $@"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"star-all-at"#,
            r#"set -- '/tmp/a*'; cat $@/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"all-star"#,
            r#"set -- '/tmp/[ab]'; cat $*/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"quoted-all-star"#,
            r#"set -- '/tmp/[ab]'; cat "$*"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"lone-all-star"#,
            r#"set -- '/tmp/[ab]/*.rs'; cat $*"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"star-all-star"#,
            r#"set -- '/tmp/a*'; cat $*/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"array-at"#,
            r#"arr=('/tmp/[ab]'); cat ${arr[@]}/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"quoted-array-at"#,
            r#"arr=('/tmp/[ab]'); cat "${arr[@]}"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"lone-array-at"#,
            r#"arr=('/tmp/[ab]/*.rs'); cat ${arr[@]}"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"star-array-at"#,
            r#"arr=('/tmp/a*'); cat ${arr[@]}/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"array-star"#,
            r#"arr=('/tmp/[ab]'); cat ${arr[*]}/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"quoted-array-star"#,
            r#"arr=('/tmp/[ab]'); cat "${arr[*]}"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"lone-array-star"#,
            r#"arr=('/tmp/[ab]/*.rs'); cat ${arr[*]}"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"star-array-star"#,
            r#"arr=('/tmp/a*'); cat ${arr[*]}/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"function-all"#,
            r#"f() { cat $@/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"function-all-quoted"#,
            r#"f() { cat "$@"/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"all-backslash"#,
            r#"set -- '/tmp/a\b'; cat $@/*.rs"#,
            r#"/tmp/ab/x.rs"#,
            r#"/tmp/a\b/x.rs"#,
        ),
        (
            r#"array-backslash"#,
            r#"arr=('/tmp/a\b'); cat ${arr[@]}/*.rs"#,
            r#"/tmp/ab/x.rs"#,
            r#"/tmp/a\b/x.rs"#,
        ),
        (
            r#"set-positional-class"#,
            r#"set -- '/tmp/[ab]'; cat $1/*.rs"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"function-positional-class"#,
            r#"f() { cat $1/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/b/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"set-positional-star"#,
            r#"set -- '/tmp/a*'; cat ${1}/*.rs"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"function-positional-star"#,
            r#"f() { cat ${1}/*.rs; }; f '/tmp/a*'"#,
            r#"/tmp/abc/x.rs"#,
            r#"/tmp/b/x.rs"#,
        ),
        (
            r#"quoted-set-positional"#,
            r#"set -- '/tmp/[ab]'; cat "$1"/*.rs"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"quoted-function-positional"#,
            r#"f() { cat "${1}"/*.rs; }; f '/tmp/[ab]'"#,
            r#"/tmp/[ab]/x.rs"#,
            r#"/tmp/a/x.rs"#,
        ),
        (
            r#"lone-positional-pattern"#,
            r#"set -- '/tmp/[ab]/*.rs'; cat $1"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"split-positional-pattern"#,
            r#"set -- '/tmp/[ab]/*.rs /tmp/c/*.rs'; cat $1"#,
            r#"/tmp/a/x.rs"#,
            r#"/tmp/[ab]/x.rs"#,
        ),
        (
            r#"positional-backslash"#,
            r#"set -- '/tmp/a\b'; cat $1/*.rs"#,
            r#"/tmp/ab/x.rs"#,
            r#"/tmp/a\b/x.rs"#,
        ),
        (
            r#"quoted-positional-backslash"#,
            r#"set -- '/tmp/a\b'; cat "$1"/*.rs"#,
            r#"/tmp/a\b/x.rs"#,
            r#"/tmp/ab/x.rs"#,
        ),
        (
            "escaped-brackets",
            r"cat /tmp/\[ab\]/*.rs",
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        (
            "quoted-brackets",
            r#"cat /tmp/"[ab]"/*.rs"#,
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        (
            "literal-backslash",
            r"cat /tmp/a\\b/*.rs",
            r"/tmp/a\b/x.rs",
            "/tmp/ab/x.rs",
        ),
        (
            "unquoted-bound-backslash",
            r"P='/tmp/a\b'; cat $P/*.rs",
            "/tmp/ab/x.rs",
            r"/tmp/a\b/x.rs",
        ),
        (
            "quoted-bound-backslash",
            r#"P='/tmp/a\b'; cat "$P"/*.rs"#,
            r"/tmp/a\b/x.rs",
            "/tmp/ab/x.rs",
        ),
        (
            "unquoted-bound-class",
            r#"P='/tmp/[ab]'; cat $P/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            "unquoted-bound-star",
            r#"P='/tmp/a*'; cat $P/*.rs"#,
            "/tmp/abc/x.rs",
            "/tmp/b/x.rs",
        ),
        (
            "embedded-bound-class",
            r#"P='[ab]'; cat /tmp/${P}/*.rs"#,
            "/tmp/b/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            "quoted-bound-class",
            r#"P='/tmp/[ab]'; cat "$P"/*.rs"#,
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        (
            "quoted-bound-star",
            r#"P='a*'; cat /tmp/"${P}"/*.rs"#,
            "/tmp/a*/x.rs",
            "/tmp/abc/x.rs",
        ),
        (
            "lone-bound-pattern",
            r#"P='/tmp/[ab]/*.rs'; cat $P"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            "assignment-copy-unquoted",
            r#"P='/tmp/[ab]'; Q=$P; cat $Q/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            "assignment-copy-quoted",
            r#"P='/tmp/[ab]'; Q=$P; cat "$Q"/*.rs"#,
            "/tmp/[ab]/x.rs",
            "/tmp/a/x.rs",
        ),
        (
            "split-bound-patterns",
            r#"P='/tmp/[ab]/*.rs /tmp/c/*.rs'; cat $P"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
        (
            "bound-default-expansion",
            r#"P='/tmp/[ab]'; cat ${P:-/tmp/c}/*.rs"#,
            "/tmp/a/x.rs",
            "/tmp/[ab]/x.rs",
        ),
    ] {
        let idx = index(
            &format!("resource-glob-{case}"),
            &format!("#!/bin/sh\n{source}\n"),
        );
        for (path, expected) in [(target, 1), (excluded, 0)] {
            let resource = ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: path.into() },
            };
            let selector = typed_selector(&resource);
            let report = reach(
                &idx,
                &Selector::parse(&selector).unwrap(),
                Some("filesystem.read"),
            );
            assert_eq!(
                report.payload.as_reach().unwrap().matches.len(),
                expected,
                "{case}: {path}"
            );
        }
    }

    let idx = index(
        "resource-glob-dot-delete",
        "#!/bin/sh\ncd /srv/app\nrm -rf ./build/*\n",
    );
    let resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/srv/app/build/o.o".into(),
        },
    };
    let selector = typed_selector(&resource);
    let report = reach(
        &idx,
        &Selector::parse(&selector).unwrap(),
        Some("filesystem.delete"),
    );
    assert_eq!(unknown_effects(&report).count(), 1);

    let idx = index(
        "resource-glob-segments",
        "#!/bin/sh\ncat /tmp/a/b /tmp/.hidden /tmp/a /worker/x\n",
    );
    for (selector, expected) in [("fs:/tmp/*", 1), ("fs:/tmp/**", 3), ("fs:/work", 0)] {
        let report = reach(
            &idx,
            &Selector::parse(selector).unwrap(),
            Some("filesystem.read"),
        );
        assert_eq!(
            report.payload.as_reach().unwrap().matches.len(),
            expected,
            "{selector}"
        );
    }
    let idx = index(
        "resource-glob-limit",
        &format!("#!/bin/sh\ncat /tmp/{}\n", "a".repeat(1024)),
    );
    let selector = Selector::parse(&format!("fs:/tmp/{}", "*a".repeat(1024))).unwrap();
    let report = reach(&idx, &selector, Some("filesystem.read"));
    assert_eq!(unknown_effects(&report).count(), 1);
    assert!(unknown_effects(&report).any(|hit| matches!(
        hit.matched,
        effinterp_proto::Match::Indeterminate {
            reason: effinterp_proto::MatchReason::Limit
        }
    )));
}

#[test]
fn scoped_queries_survive_incremental_updates() {
    use effinterp_repo::{RepoChange, apply_changes, normalize_surface};
    let source = "#!/bin/sh\ngcloud compute instances delete web --project one --zone us-central1-a\nkafka-console-producer --topic orders --bootstrap-server a:9092\naws s3 rm s3://bucket/$KEY\n";
    let root = repo("scoped-resource-storage", source);
    let mut before = build_index(&root, IndexLimits::default());
    let forward = effects_of(&before, "run.sh").unwrap();
    for fact in forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|f| matches!(f.operation.domain(), "cloud" | "messaging"))
    {
        let selector = if fact.operation.0 == "cloud.object.delete" {
            Selector::parse("obj:bucket").unwrap()
        } else {
            Selector::parse(&typed_selector(&fact.resource)).unwrap()
        };
        let live = reach(&before, &selector, Some(fact.operation.as_str()));
        let matched = selector.match_effect(fact);
        match matched {
            effinterp_proto::Match::Satisfied { .. } => assert!(
                live.payload
                    .as_reach()
                    .unwrap()
                    .matches
                    .iter()
                    .any(|hit| hit.fact == *fact && hit.matched == matched)
            ),
            effinterp_proto::Match::Indeterminate { .. } => assert!(
                unknown_effects(&live).any(|hit| hit.fact == fact && *hit.matched == matched)
            ),
            effinterp_proto::Match::NotSatisfied => {
                panic!("self selector must retain a fact or uncertainty")
            }
        }
    }
    assert!(Selector::parse("cloud:@not-hex").is_err());
    let after_source = source
        .replace("--project one", "--project two")
        .replace("a:9092", "alias:9092");
    std::fs::write(root.join("run.sh"), after_source).unwrap();
    apply_changes(
        &mut before,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("run.sh".into())],
    );
    let clean = build_index(&root, IndexLimits::default());
    assert_eq!(normalize_surface(&before), normalize_surface(&clean));
    let after = effects_of(&before, "run.sh").unwrap();
    let resources = |envelope: &effinterp_proto::RepoQueryEnvelope, operation: &str| {
        envelope
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .filter(|fact| fact.operation.as_str() == operation)
            .map(|fact| effinterp_proto::canonical_json(&fact.resource))
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_ne!(
        resources(&forward, "cloud.resource.delete"),
        resources(&after, "cloud.resource.delete")
    );
}

#[test]
fn infrastructure_selectors_preserve_scope_and_unresolved_target_evidence() {
    let root = repo_files(
        "infrastructure-selectors",
        &[
            ("package.json", r#"{"scripts":{"run":"sh run.sh"}}"#),
            (
                "run.sh",
                "#!/bin/sh\nkubectl delete deployment.apps/api -n one --server=https://a\nkubectl delete deployment.apps/api -n two --server=https://a\nkubectl delete deployment.other/api -n one --server=https://b\nterraform destroy\n",
            ),
            ("main.tf", "resource \"aws_instance\" \"web\" {}"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let forward = effects_of(&index, "package.json:scripts.run").unwrap();
    let rows: Vec<_> = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|e| {
            matches!(
                &e.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::KubernetesResource { .. }
                        | ResourceIdentity::ManagedInfrastructure {
                            address: Some(_),
                            ..
                        }
                }
            )
        })
        .collect();
    assert_eq!(rows.len(), 4);
    let mut selectors = std::collections::BTreeSet::new();
    for row in rows {
        let selector = typed_selector(&row.resource);
        assert!(selectors.insert(selector.clone()));
        let report = reach(
            &index,
            &Selector::parse(&selector).unwrap(),
            Some(row.operation.as_str()),
        );
        assert!(unknown_effects(&report).any(|hit| hit.fact.resource == row.resource));
        assert!(report.payload.as_reach().unwrap().matches.is_empty());
    }
}

#[test]
fn artifact_selectors_preserve_namespaces_across_incremental_and_saved_indexes() {
    use effinterp_proto::{ArtifactEcosystem, ArtifactReference};
    use effinterp_repo::{RepoChange, apply_changes, normalize_surface, save_index};
    let manifest =
        r#"{"name":"api","version":"1.2.3","publishConfig":{"registry":"https://npm.example"}}"#;
    let root = repo_files(
        "artifact-queries",
        &[
            (
                "package.json",
                r#"{"scripts":{"ship":"docker push ghcr.io/acme/api:v2; docker push registry.example:5000/acme/api:v2; docker push ghcr.io/acme/api:v3; npm publish pkg --ignore-scripts; gh release delete v2 -R acme/api --yes; gh release delete v3 -R github.com/acme/api --yes"}}"#,
            ),
            ("pkg/package.json", manifest),
            (
                "unpublish.sh",
                "#!/bin/sh\nnpm unpublish api --registry https://npm.example --force --ignore-scripts\n",
            ),
            (
                "symbolic.sh",
                "#!/bin/sh\ndocker push ghcr.io/acme/api:$TAG\n",
            ),
            ("hub.sh", "#!/bin/sh\ndocker push acme/api:v2\n"),
            (
                "hub-alias.sh",
                "#!/bin/sh\ndocker push index.docker.io/acme/api:v2\n",
            ),
            ("npm-options.sh", "#!/bin/sh\nnpm --prefix sub publish\n"),
            ("symbolic-namespace.sh", "#!/bin/sh\ndocker push $ORG/api\n"),
        ],
    );
    let mut idx = build_index(&root, IndexLimits::default());
    let forward = effects_of(&idx, "package.json:scripts.ship").unwrap();
    let artifacts: Vec<_> = forward
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|e| {
            e.operation.domain() == "artifact" && !e.operation.as_str().ends_with("_request")
        })
        .collect();
    assert_eq!(artifacts.len(), 6);
    {
        let human = reach(
            &idx,
            &Selector::parse("artifact:acme/api").unwrap(),
            Some("artifact.publish"),
        );
        assert!(
            unknown_effects(&human).any(|hit| hit.fact.entrypoint == "package.json:scripts.ship"
                && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. }))
        );
        assert!(
            unknown_effects(&human).any(|hit| hit.fact.entrypoint == "symbolic.sh"
                && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. }))
        );
        let hub = effects_of(&idx, "hub.sh").unwrap();
        let artifact = hub
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .find(|effect| effect.operation.domain() == "artifact")
            .unwrap();
        let selector = Selector::parse(&typed_selector(&artifact.resource)).unwrap();
        let result = reach(&idx, &selector, Some("artifact.publish"));
        for entrypoint in ["hub.sh", "hub-alias.sh"] {
            assert!(
                result
                    .payload
                    .as_reach()
                    .unwrap()
                    .matches
                    .iter()
                    .any(|hit| hit.fact.entrypoint == entrypoint
                        && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
            );
        }
        assert!(
            human
                .payload
                .as_reach()
                .unwrap()
                .indeterminate
                .iter()
                .filter_map(|row| match row {
                    effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
                    _ => None,
                })
                .any(|row| { row.entrypoint == "npm-options.sh" && row.domain == "artifact" })
        );
    }
    for (endpoint, name) in [("docker.io", "acme/api"), ("registry.example", "api")] {
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact {
                ecosystem: ArtifactEcosystem::Oci,
                endpoint: Box::new(ResourceExpr::Literal {
                    value: endpoint.into(),
                }),
                name: Box::new(ResourceExpr::Literal { value: name.into() }),
                reference: Box::new(ArtifactReference::Tag {
                    value: ResourceExpr::Literal {
                        value: "latest".into(),
                    },
                }),
            },
        };
        let selector = Selector::parse(&typed_selector(&resource)).unwrap();
        assert!(
            unknown_effects(&reach(&idx, &selector, Some("artifact.publish"))).any(|hit| hit
                .fact
                .entrypoint
                == "symbolic-namespace.sh"
                && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. }))
        );
    }
    for row in &artifacts {
        let selector = typed_selector(&row.resource);
        let selector = Selector::parse(&selector).unwrap();
        let result = reach(&idx, &selector, Some(row.operation.as_str()));
        if matches!(
            &row.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Artifact {
                    ecosystem: ArtifactEcosystem::GithubRelease,
                    endpoint,
                    ..
                }
            } if matches!(endpoint.as_ref(), ResourceExpr::Unresolved { .. })
        ) {
            assert!(result.payload.as_reach().unwrap().matches.is_empty());
            assert!(unknown_effects(&result).any(|hit| hit.fact.resource == row.resource));
            continue;
        }
        assert_eq!(
            result
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .filter(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
                .count(),
            1,
            "row: {:?}; result: {:?}",
            row.resource,
            result.payload.as_reach().unwrap().matches
        );
        if matches!(&row.resource, ResourceExpr::Concrete { identity: ResourceIdentity::Artifact { ecosystem: ArtifactEcosystem::Oci, endpoint, .. } } if **endpoint == ResourceExpr::Literal { value: "ghcr.io".into() })
        {
            assert!(
                unknown_effects(&result).any(|hit| hit.fact.entrypoint == "symbolic.sh"
                    && matches!(hit.matched, effinterp_proto::Match::Indeterminate { .. }))
            );
        }
    }
    let package = artifacts
        .iter()
        .find(|e| {
            matches!(
                &e.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Artifact {
                        ecosystem: ArtifactEcosystem::Npm,
                        ..
                    }
                }
            )
        })
        .unwrap()
        .resource
        .clone();
    let version_selector = Selector::parse(&typed_selector(&package)).unwrap();
    let version = reach(&idx, &version_selector, Some("artifact.delete"));
    assert!(version.payload.as_reach().unwrap().matches.is_empty());
    assert!(!unknown_effects(&version).any(|hit| hit.fact.entrypoint == "unpublish.sh"));
    let mut different = package.clone();
    if let ResourceExpr::Concrete {
        identity: ResourceIdentity::Artifact { ecosystem, .. },
    } = &mut different
    {
        *ecosystem = ArtifactEcosystem::Oci;
    }
    let selector = Selector::parse(&typed_selector(&different)).unwrap();
    assert!(
        reach(&idx, &selector, Some("artifact.publish"))
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .all(|hit| !matches!(hit.matched, effinterp_proto::Match::Satisfied { .. }))
    );
    std::fs::write(
        root.join("pkg/package.json"),
        manifest.replace("1.2.3", "1.2.4"),
    )
    .unwrap();
    apply_changes(
        &mut idx,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("pkg/package.json".into())],
    );
    let rebuilt = build_index(&root, IndexLimits::default());
    assert_eq!(normalize_surface(&idx), normalize_surface(&rebuilt));
    assert_eq!(save_index(&idx), save_index(&rebuilt));
    let changed = effects_of(&idx, "package.json:scripts.ship").unwrap();
    assert!(changed.payload.as_effects().unwrap().effects.iter().any(|e| matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::Artifact { reference, .. } } if matches!(reference.as_ref(), ArtifactReference::Version { value: ResourceExpr::Literal { value } } if value == "1.2.4"))));
    assert!(
        !changed
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|e| e.resource == package)
    );
}
