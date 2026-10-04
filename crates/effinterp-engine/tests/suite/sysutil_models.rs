//! Tests for the system-utility, transfer, and package-manager models.

use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn plan(argv: &[&str]) -> Plan {
    let p = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&p).unwrap();
    p
}

fn context_plan(argv: &[&str]) -> Plan {
    let p = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: HostContext {
                env: [("UNRELATED".to_string(), "value".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&p).unwrap();
    p
}

fn env_plan(argv: &[&str], name: &str, value: &str) -> Plan {
    let p = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: HostContext {
                env: [(name.to_string(), value.to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&p).unwrap();
    p
}

fn fs_path(e: &effinterp_proto::Effect) -> Option<&str> {
    resource_fs_path(&e.resource)
}

fn resource_fs_path(resource: &ResourceExpr) -> Option<&str> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

fn has(plan: &Plan, op: &str, path: &str) -> bool {
    plan.effects
        .iter()
        .any(|e| e.operation.0 == op && fs_path(e) == Some(path))
}

fn has_op(plan: &Plan, op: &str) -> bool {
    plan.effects.iter().any(|e| e.operation.0 == op)
}

// --- find ---

#[test]
fn find_delete_applies_selectors_to_the_deleted_set() {
    let p = plan(&["find", "/data", "-name", "*.log", "-delete"]);
    assert!(has(&p, "filesystem.read", "/data"));
    let del = p
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("delete");
    assert!(matches!(
        &del.resource,
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob }
        } if glob == "/data/**/*.log"
    ));
    assert!(!del.attributes.contains_key("recursive"));
}

#[test]
fn cryptsetup_erase_writes_the_device_keyslots() {
    let p = plan(&["cryptsetup", "erase", "/dev/sda"]);
    let write = p
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("device write");
    assert_eq!(fs_path(write), Some("/dev/sda"));
    assert_eq!(write.attributes["raw_device"], AttrValue::Bool(true));
    assert_eq!(write.attributes["keyslots_erased"], AttrValue::Bool(true));
    assert!(p.boundaries.is_empty());
}

#[test]
fn find_without_delete_only_reads() {
    let p = plan(&["find", "/etc", "-type", "f"]);
    assert!(has(&p, "filesystem.read", "/etc"));
    assert!(!has_op(&p, "filesystem.delete"));
    assert!(!has_op(&p, "filesystem.write"));
}

#[test]
fn find_output_file_actions_write_the_file_they_name() {
    for action in ["-fprint", "-fprint0", "-fls"] {
        let p = plan(&["find", "/srv", "-name", "*.log", action, "/out/list"]);
        assert!(has(&p, "filesystem.write", "/out/list"), "{action}");
        assert!(has(&p, "filesystem.read", "/srv"), "{action}");
    }
    // The format after the file is neither written nor read as a test.
    let p = plan(&["find", "/srv", "-fprintf", "/out/list", "%p\\n", "-delete"]);
    assert!(has(&p, "filesystem.write", "/out/list"));
    assert!(has(&p, "filesystem.delete", "/srv"));
    let writes = p
        .effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.write");
    assert_eq!(writes.count(), 1);
}

#[test]
fn find_exec_nests_the_command_with_root_and_descendant_matches() {
    // An action without its `;` or `+` terminator is a usage error: find
    // reports it and exits before it traverses the root or runs the command.
    let malformed = plan(&["find", "/tmp", "-exec", "rm", "-rf", "/", "{}"]);
    assert!(!has_op(&malformed, "filesystem.delete"));
    assert!(!has(&malformed, "filesystem.read", "/tmp"));
    assert!(
        malformed.boundaries.is_empty(),
        "{:?}",
        malformed.boundaries
    );
    let p = context_plan(&["find", "/tmp", "-type", "f", "-exec", "rm", "-f", "{}", ";"]);
    assert!(has_op(&p, "filesystem.delete"));
    let del = p
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    let ResourceExpr::Union { alternatives } = &del.resource else {
        panic!("find match must include the root and its descendants");
    };
    assert!(
        alternatives
            .iter()
            .any(|resource| resource_fs_path(resource) == Some("/tmp"))
    );
    assert!(alternatives.iter().any(
        |resource| matches!(resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/tmp/**")
    ));
    assert!(p.execution_graph.nodes.iter().any(|n| matches!(
        &n.subject,
        Subject::Exec { argv, .. } if argv.first().map(String::as_str) == Some("rm")
    )));
}

#[test]
fn find_exec_without_a_root_uses_the_current_directory() {
    let p = context_plan(&["find", "-exec", "rm", "-f", "{}", ";"]);
    let del = p
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    let ResourceExpr::Union { alternatives } = &del.resource else {
        panic!("default find match must include cwd and its descendants");
    };
    assert!(
        alternatives
            .iter()
            .any(|resource| resource_fs_path(resource) == Some("/w"))
    );
    assert!(alternatives.iter().any(
        |resource| matches!(resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/w/**")
    ));
}

#[test]
fn find_leading_options_precede_the_start_paths() {
    // Only -L descends through symbolic links, so only it leaves the matches
    // below a start path uncertain.
    for (option, follows) in [("-L", true), ("-P", false)] {
        let p = plan(&[
            "find", option, "/etc", "-name", "passwd", "-exec", "rm", "-rf", "{}", "+",
        ]);
        assert!(has(&p, "filesystem.delete", "/etc/passwd"), "{option}");
        assert!(!has(&p, "filesystem.read", "/w"), "{option}");
        assert_eq!(
            p.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE
            }),
            follows,
            "{option}"
        );
    }
}

#[test]
fn find_scope_does_not_depend_on_unrelated_environment() {
    for argv in [
        &["find", "/tmp", "-exec", "rm", "-f", "{}", ";"][..],
        &["find", "-exec", "rm", "-f", "{}", ";"][..],
    ] {
        let plain = plan(argv);
        let contextual = context_plan(argv);
        let delete = plain
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(matches!(delete.resource, ResourceExpr::Union { .. }));
        assert_eq!(
            delete.resource,
            contextual
                .effects
                .iter()
                .find(|effect| effect.operation.0 == "filesystem.delete")
                .unwrap()
                .resource
        );
    }
}

// --- kill family ---

#[test]
fn kill_pid_signals_an_opaque_process() {
    let p = plan(&["kill", "-9", "1234"]);
    let sig = p
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.signal")
        .expect("signal");
    assert!(matches!(sig.resource, ResourceExpr::Unresolved { .. }));
    assert_eq!(
        sig.attributes["force"],
        effinterp_proto::AttrValue::Bool(true)
    );
}

#[test]
fn kill_signal_option_value_is_not_a_process_target() {
    let p = plan(&["kill", "-s", "TERM", "1234"]);
    let signals = p
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "process.signal")
        .collect::<Vec<_>>();
    assert_eq!(signals.len(), 1);
    assert!(matches!(
        signals[0].resource,
        ResourceExpr::Unresolved { .. }
    ));
    assert!(!signals[0].attributes.contains_key("force"));
}

#[test]
fn killall_signals_a_named_executable() {
    let p = plan(&["killall", "nginx"]);
    let sig = p
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.signal")
        .unwrap();
    assert!(matches!(
        &sig.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::Process { executable, .. } } if executable == "nginx"
    ));
}

// --- mount ---

#[test]
fn mount_targets_the_mountpoint() {
    let p = plan(&["mount", "-t", "ext4", "/dev/sdb1", "/mnt/data"]);
    assert!(has(&p, "filesystem.mount", "/mnt/data"));
}

#[test]
fn umount_targets_the_mountpoint() {
    let p = plan(&["umount", "/mnt/data"]);
    assert!(has(&p, "filesystem.unmount", "/mnt/data"));
}

// --- zip family ---

#[test]
fn unzip_reads_archive_and_writes_into_dir() {
    let p = plan(&["unzip", "/tmp/a.zip", "-d", "/out"]);
    assert!(has(&p, "filesystem.read", "/tmp/a.zip"));
    assert!(p.effects.iter().any(|e| e.operation.0 == "filesystem.write"
        && matches!(&e.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/out/**")));
}

#[test]
fn gzip_models_input_and_derived_output_identity() {
    let p = plan(&["gzip", "/tmp/big.log"]);
    let environment = p
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name }
                    } if name == "GZIP"
                )
        })
        .expect("gzip environment dependency");
    assert_eq!(
        environment.request_assurance,
        effinterp_proto::RequestAssurance::Conservative
    );
    assert_eq!(environment.modality, effinterp_proto::Modality::May);
    assert!(has(&p, "filesystem.read", "/tmp/big.log"));
    assert!(has(&p, "filesystem.write", "/tmp/big.log.gz"));
    assert!(has(&p, "filesystem.delete", "/tmp/big.log"));
    assert_eq!(
        p.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap()
            .attributes["access_purpose"],
        effinterp_proto::AttrValue::String("program_input".into())
    );

    let custom = plan(&["gzip", "-kS.packed", "/tmp/big.log"]);
    assert!(has(&custom, "filesystem.read", "/tmp/big.log"));
    assert!(has(&custom, "filesystem.write", "/tmp/big.log.packed"));
    assert!(!has_op(&custom, "filesystem.delete"));

    let gunzip = plan(&["gunzip", "/tmp/archive.tgz"]);
    assert!(has(&gunzip, "filesystem.read", "/tmp/archive.tgz"));
    assert!(has(&gunzip, "filesystem.write", "/tmp/archive.tar"));
    assert!(has(&gunzip, "filesystem.delete", "/tmp/archive.tgz"));

    let restored = plan(&["gunzip", "--no-name", "-N", "/tmp/carrier.gz"]);
    assert!(has(&restored, "filesystem.read", "/tmp/carrier.gz"));
    assert!(!has_op(&restored, "filesystem.write"));
    assert!(has(&restored, "filesystem.delete", "/tmp/carrier.gz"));
    assert!(!restored.boundaries.is_empty());

    let suffix_named = plan(&["gunzip", "--name", "-n", "-k", "/tmp/carrier.gz"]);
    assert!(has(&suffix_named, "filesystem.read", "/tmp/carrier.gz"));
    assert!(has(&suffix_named, "filesystem.write", "/tmp/carrier"));
    assert!(!has_op(&suffix_named, "filesystem.delete"));
}

#[test]
fn gzip_stdout_and_nontransforming_modes_do_not_mutate_inputs() {
    for argv in [
        &["gzip", "-c", "/tmp/big.log"][..],
        &["gunzip", "-c", "/tmp/big.log.gz"],
        &["gzip", "-l", "/tmp/big.log.gz"],
        &["gzip", "-t", "/tmp/big.log.gz"],
    ] {
        let p = plan(argv);
        assert!(has_op(&p, "filesystem.read"), "{argv:?}");
        assert!(!has_op(&p, "filesystem.write"), "{argv:?}");
        assert!(!has_op(&p, "filesystem.delete"), "{argv:?}");
    }
}

#[test]
fn gzip_refuses_to_invent_outputs_for_unresolved_grammars() {
    for argv in [
        &["gzip", "--quiet=garbage", "/tmp/big.log"][..],
        &["gzip", "-S", "/bad", "/tmp/big.log"],
        &["gzip", "--future", "value", "/tmp/big.log"],
        &["gzip", "-Z", "/tmp/big.log"],
    ] {
        let p = plan(argv);
        assert!(!has_op(&p, "filesystem.write"), "{argv:?}");
        assert!(!has_op(&p, "filesystem.delete"), "{argv:?}");
        assert!(!p.boundaries.is_empty(), "{argv:?}");
    }

    let recursive = plan(&["gzip", "-r", "/tmp/tree"]);
    assert!(has(&recursive, "filesystem.read", "/tmp/tree"));
    assert!(!has_op(&recursive, "filesystem.write"));
    assert!(!has_op(&recursive, "filesystem.delete"));
    assert!(!recursive.boundaries.is_empty());

    for argv in [
        &["gunzip", "/tmp/plain"][..],
        &["gunzip", "-c", "/tmp/plain"],
    ] {
        let suffix_search = plan(argv);
        assert!(!has_op(&suffix_search, "filesystem.read"), "{argv:?}");
        assert!(!has_op(&suffix_search, "filesystem.write"), "{argv:?}");
        assert!(!has_op(&suffix_search, "filesystem.delete"), "{argv:?}");
        assert!(!suffix_search.boundaries.is_empty(), "{argv:?}");
    }

    let inherited = env_plan(&["gzip", "-k", "/tmp/big.log"], "GZIP", "-d -S .old");
    let read = inherited
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.read" && fs_path(effect) == Some("/tmp/big.log")
        })
        .expect("conservative possible read");
    assert!(!read.attributes.contains_key("access_purpose"));
    assert!(!has_op(&inherited, "filesystem.write"));
    assert!(!has_op(&inherited, "filesystem.delete"));
    assert!(!has_op(&inherited, "process.stream_transform"));
    assert!(!inherited.boundaries.is_empty());
}

// --- chattr ---

#[test]
fn chattr_is_a_metadata_change_not_a_mode_write() {
    let p = plan(&["chattr", "+i", "/etc/passwd"]);
    assert!(has(&p, "filesystem.metadata", "/etc/passwd"));
    assert!(p.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.metadata"
            && effect.attributes.get("action") == Some(&AttrValue::String("chattr".into()))
    }));
    // The +i spec is not itself a path.
    assert!(!p.effects.iter().any(|e| fs_path(e) == Some("/w/+i")));
}

#[test]
fn setfacl_specs_are_not_metadata_targets_and_edits_are_permission_changes() {
    for argv in [
        &["setfacl", "-m", "u:alice:rwx", "/srv/data"][..],
        &["setfacl", "-x", "u:bob", "/srv/data"],
        &["setfacl", "--set", "u::rw,g::r,o::-", "/srv/data"],
        &["setfacl", "-Rm", "u:alice:rwx", "/srv/data"],
        &["setfacl", "-dm", "u:alice:rwx", "/srv/data"],
        &["setfacl", "-nm", "u:alice:rwx", "/srv/data"],
        &["setfacl", "-Rx", "u:bob", "/srv/data"],
    ] {
        let p = plan(argv);
        let targets = p
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.metadata")
            .filter_map(fs_path)
            .collect::<Vec<_>>();
        assert_eq!(targets, vec!["/srv/data"], "{argv:?}");
        assert!(p.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.metadata"
                && effect.attributes.get("action") == Some(&AttrValue::String("chmod".into()))
                && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
        }));
    }
    // `--test` only lists the ACLs an edit would produce.
    for argv in [
        &["setfacl", "--test", "-R", "-m", "u:alice:rwx", "/etc"][..],
        &["setfacl", "-tm", "u:alice:rwx", "/srv/data"],
    ] {
        let p = plan(argv);
        assert!(
            p.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.metadata"),
            "{argv:?}"
        );
    }
    // Regression: an `other` entry granting write was never a world-write
    // fact, so fs-permission-weaken missed `setfacl -m o::rwx`. Default
    // entries, a later entry that takes write back, and a `--set` that omits
    // `other` grant nothing on the target.
    let data: &[&str] = &["/srv/data"];
    for (argv, granted) in [
        (&["setfacl", "-m", "o::rwx", "/srv/data"][..], data),
        (&["setfacl", "-m", "u:alice:r,other:rw", "/srv/data"], data),
        (&["setfacl", "--set", "u::rw,g::r,o::7", "/srv/data"], data),
        (&["setfacl", "-m", "o::rwx", "-m", "o::r", "/srv/data"], &[]),
        (
            &["setfacl", "-m", "o::rwx", "--set", "u::rw", "/srv/data"],
            &[],
        ),
        (&["setfacl", "-m", "d:o::rwx", "/srv/data"], &[]),
        (&["setfacl", "-dm", "o::rwx", "/srv/data"], &[]),
        (&["setfacl", "--set", "u::rw,g::r,o::-", "/srv/data"], &[]),
        // Regression: the file name after -M was parsed as the ACL itself.
        (&["setfacl", "-M", "o::rw", "/srv/data"], &[]),
        (
            &["setfacl", "-m", "o::rwx", "-X", "o::rw", "/srv/data"],
            &[],
        ),
        // Regression: one result for the whole command was applied to every
        // file. setfacl applies options in order: -d only promotes later
        // entries, each file gets the changes given since the previous one,
        // and a --set of default entries leaves the access ACL alone.
        (
            &["setfacl", "-m", "o::rwx", "-d", "-m", "o::r-x", "/srv/data"],
            data,
        ),
        (
            &[
                "setfacl",
                "-m",
                "o::rwx",
                "/srv/data",
                "-m",
                "o::r-x",
                "/srv/other",
            ],
            data,
        ),
        (
            &[
                "setfacl",
                "-m",
                "o::r-x",
                "/srv/other",
                "-m",
                "o::rwx",
                "/srv/data",
            ],
            data,
        ),
        (
            &[
                "setfacl",
                "-m",
                "o::rwx",
                "--set",
                "d:u::rwx,d:g::r-x,d:o::r-x",
                "/srv/data",
            ],
            data,
        ),
        // Regression: --version and --help exit where they appear, but the
        // files after them were still changed.
        (&["setfacl", "--version", "-m", "o::rwx", "/srv/data"], &[]),
        (&["setfacl", "-m", "o::rwx", "--help", "/srv/data"], &[]),
        (
            &[
                "setfacl",
                "-m",
                "o::rwx",
                "/srv/data",
                "--help",
                "/srv/other",
            ],
            data,
        ),
    ] {
        let p = plan(argv);
        let targets: Vec<_> = p
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.as_str() == "filesystem.metadata"
                    && effect.attributes.get("world_write") == Some(&AttrValue::Bool(true))
            })
            .filter_map(fs_path)
            .collect();
        assert_eq!(targets, granted, "{argv:?}");
    }
}

/// The `(target, action, recursive, world_write)` of each metadata change.
fn metadata_changes(p: &Plan) -> Vec<(String, String, bool, bool)> {
    let flag = |effect: &effinterp_proto::Effect, key: &str| {
        effect.attributes.get(key) == Some(&AttrValue::Bool(true))
    };
    p.effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.metadata")
        .map(|effect| {
            let action = match effect.attributes.get("action") {
                Some(AttrValue::String(action)) => action.clone(),
                _ => String::new(),
            };
            (
                fs_path(effect).unwrap_or_default().to_string(),
                action,
                flag(effect, "recursive"),
                flag(effect, "world_write"),
            )
        })
        .collect()
}

#[test]
fn macos_chmod_acl_edits_are_permission_changes() {
    // Regression: `chmod +a` failed chmod's mode grammar, so an ACL entry
    // granting everyone write never reached fs-permission-weaken.
    for (argv, world_write) in [
        (&["chmod", "+a", "everyone allow write", "/p/f"][..], true),
        (
            &["chmod", "+a#", "0", "group:everyone allow add_file", "/p/f"],
            true,
        ),
        (
            &[
                "chmod",
                "=a#",
                "1",
                "everyone allow read,writesecurity",
                "/p/f",
            ],
            true,
        ),
        (&["chmod", "+ai", "everyone allow append", "/p/f"], true),
        // chmod_acl.c's `parse_entry` splits on `:` when the entry holds
        // one, skips empty permission fields, and reads one entry per line.
        (&["chmod", "+a", "everyone:allow:write", "/p/f"], true),
        (&["chmod", "+a", "group:everyone:allow write", "/p/f"], true),
        (&["chmod", "+a", "everyone allow write,read,", "/p/f"], true),
        (
            &[
                "chmod",
                "+a",
                "staff allow read\n\neveryone allow write",
                "/p/f",
            ],
            true,
        ),
        (
            &[
                "chmod",
                "+aii#",
                "0x1",
                "everyone allow write,inherited",
                "/p/f",
            ],
            true,
        ),
        (
            &["chmod", "+a#", " +2", "everyone allow write", "/p/f"],
            true,
        ),
        (&["chmod", "+a#", "", "everyone allow write", "/p/f"], true),
        (&["chmod", "-h", "+a", "everyone allow write", "/p/f"], true),
        (&["chmod", "+a", "staff allow write", "/p/f"], false),
        (&["chmod", "+a", "everyone deny write", "/p/f"], false),
        (
            &["chmod", "+a", "everyone allow read,execute", "/p/f"],
            false,
        ),
        (
            &["chmod", "+a", "everyone allow write,only_inherit", "/p/f"],
            false,
        ),
        (&["chmod", "-a", "everyone allow write", "/p/f"], false),
        (&["chmod", "-a#", "0", "/p/f"], false),
    ] {
        let p = plan(argv);
        assert_eq!(
            metadata_changes(&p),
            vec![("/p/f".into(), "chmod".into(), false, world_write)],
            "{argv:?}"
        );
        assert!(p.boundaries.is_empty(), "{argv:?}");
    }
    let p = plan(&["chmod", "-R", "+a", "everyone allow write", "/p", "/q"]);
    assert_eq!(
        metadata_changes(&p),
        vec![
            ("/p".into(), "chmod".into(), true, true),
            ("/q".into(), "chmod".into(), true, true),
        ]
    );
    // An entry chmod may reject still keeps the change, with its gap.
    for argv in [
        &["chmod", "+a", "everyone allow everything", "/p/f"][..],
        &["chmod", "+a", "everyone allow read, write", "/p/f"],
        &["chmod", "+a", "everyone allow ,", "/p/f"],
        &["chmod", "-a", "everyone", "/p/f"],
    ] {
        let p = plan(argv);
        assert_eq!(
            metadata_changes(&p),
            vec![("/p/f".into(), "chmod".into(), false, false)],
            "{argv:?}"
        );
        assert!(
            p.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{argv:?}"
        );
    }
    // Regression: chmod rejects these before changing anything, yet they
    // were certified as world-write grants with Full coverage. They go back
    // to the mode grammar, as before the ACL model.
    for argv in [
        &["chmod", "+a#", "banana", "everyone allow write", "/p/f"][..],
        &["chmod", "+a#", "129", "everyone allow write", "/p/f"],
        &["chmod", "+a#", "-1", "everyone allow write", "/p/f"],
        &["chmod", "+ax", "everyone allow write", "/p/f"],
        &["chmod", "-Rh", "+a", "everyone allow write", "/p/f"],
        &["chmod", "-R", "-h", "+a", "everyone allow write", "/p/f"],
    ] {
        let p = plan(argv);
        assert!(
            metadata_changes(&p).iter().all(|change| !change.3),
            "{argv:?}"
        );
    }
    // A position that is not literal leaves the edit's validity unknown:
    // the conservative change and its recursion stay, the grant is not
    // certified.
    let p = Engine::new()
        .analyze(&Subject::Shell {
            source: "chmod -R +a# \"$n\" 'everyone allow write' /p".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    assert_eq!(
        metadata_changes(&p),
        vec![("/p".into(), "chmod".into(), true, false)]
    );
    assert!(
        p.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
    // Modes stay with the mode grammar.
    let p = plan(&["chmod", "-R", "o+w", "/p"]);
    assert!(metadata_changes(&p).contains(&("/p".into(), "chmod".into(), true, true)));
}

fn windows_plan(argv: &[&str]) -> Plan {
    let p = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("C:\\w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&p).unwrap();
    p
}

#[test]
fn icacls_edits_are_permission_changes_and_queries_read() {
    let chmod = |recursive, world_write| {
        vec![(
            "C:/w/build".to_string(),
            "chmod".to_string(),
            recursive,
            world_write,
        )]
    };
    for (argv, changes) in [
        (
            &["icacls", "build", "/grant", "Everyone:F"][..],
            chmod(false, true),
        ),
        (
            &[
                "icacls.exe",
                "build",
                "/grant:r",
                "*S-1-1-0:(OI)(CI)M",
                "/T",
            ],
            chmod(true, true),
        ),
        (
            &["icacls", "build", "/grant", "Users:RX", "everyone:(WD,AD)"],
            chmod(false, true),
        ),
        (
            &["icacls", "build", "/grant", "Everyone:(OI)(IO)F"],
            chmod(false, false),
        ),
        (
            &["icacls", "build", "/grant", "Users:F", "/c", "/q"],
            chmod(false, false),
        ),
        (
            &["icacls", "build", "/grant", "Everyone:RX"],
            chmod(false, false),
        ),
        // Regression: a bare run of simple rights was read as one unknown
        // right, so `RW` lost its write.
        (
            &["icacls", "build", "/grant", "Everyone:RW"],
            chmod(false, true),
        ),
        (
            &["icacls", "build", "/grant", "Everyone:(OI)rxw"],
            chmod(false, true),
        ),
        (
            &["icacls", "build", "/grant", "Everyone:RXD"],
            chmod(false, false),
        ),
        (
            &["icacls", "build", "/deny", "Everyone:F"],
            chmod(false, false),
        ),
        (
            &["icacls", "build", "/remove:g", "Everyone"],
            chmod(false, false),
        ),
        (&["icacls", "build", "/reset", "/t"], chmod(true, false)),
        (&["icacls", "build", "/inheritance:r"], chmod(false, false)),
        (
            &["icacls", "build", "/setowner", "Administrators", "/T"],
            vec![("C:/w/build".into(), "chown".into(), true, false)],
        ),
    ] {
        let p = windows_plan(argv);
        assert_eq!(metadata_changes(&p), changes, "{argv:?}");
        assert!(p.boundaries.is_empty(), "{argv:?}");
    }
    // Displaying, checking or saving the ACLs changes none of them.
    for argv in [
        &["icacls", "build"][..],
        &["icacls", "build", "/verify", "/T"],
        &["icacls", "build", "/findsid", "Everyone"],
        &["icacls", "build", "/save", "acl.txt", "/T"],
    ] {
        let p = windows_plan(argv);
        assert!(metadata_changes(&p).is_empty(), "{argv:?}");
        assert!(has(&p, "filesystem.read", "C:/w/build"), "{argv:?}");
        assert!(p.boundaries.is_empty(), "{argv:?}");
    }
    assert!(has(
        &windows_plan(&["icacls", "build", "/save", "acl.txt"]),
        "filesystem.write",
        "C:/w/acl.txt"
    ));
    // A grant or switch the model cannot read keeps the change, with its gap.
    for argv in [
        &["icacls", "build", "/grant", "Everyone:everything"][..],
        &["icacls", "build", "/grant", "Everyone:RZ"],
        &["icacls", "build", "/restore", "acl.txt"],
    ] {
        let p = windows_plan(argv);
        assert_eq!(metadata_changes(&p), chmod(false, false), "{argv:?}");
        assert!(
            p.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{argv:?}"
        );
    }
}

#[test]
fn setfacl_recursive_long_option() {
    for argv in [
        &["setfacl", "--rec", "-m", "u:test:r", "/"][..],
        &["/usr/bin/setfacl", "--recursive", "-m", "u:test:r", "/"],
        &["setfacl", "-Rm", "u:test:r", "/"],
    ] {
        let p = plan(argv);
        assert!(
            p.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.metadata"
                    && fs_path(effect) == Some("/")
                    && effect.attributes.get("recursive") == Some(&AttrValue::Bool(true))
            }),
            "{argv:?}"
        );
        assert!(p.boundaries.is_empty(), "{argv:?}");
    }
    // `--test` only prints the ACLs the change would produce.
    for argv in [
        &["/usr/bin/setfacl", "--rec", "--test", "-m", "u:test:r", "/"][..],
        &["setfacl", "-Rtm", "u:test:r", "/"],
    ] {
        let p = plan(argv);
        assert!(
            !p.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.metadata"),
            "{argv:?}"
        );
        assert!(p.boundaries.is_empty(), "{argv:?}");
    }
    let p = plan(&["setfacl", "--bogus", "-m", "u:test:r", "/srv/data"]);
    assert!(
        p.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
}

// --- rsync / scp ---

#[test]
fn rsync_to_remote_uploads_and_reads_local() {
    let p = plan(&["rsync", "-a", "--delete", "/local/", "backup.host:/remote/"]);
    assert!(has(&p, "filesystem.read", "/local"));
    let upload = p
        .effects
        .iter()
        .find(|e| e.operation.0 == "network.upload"
            && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "backup.host"))
        .expect("remote upload");
    assert_eq!(
        upload.attributes.get("delete"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(
        p.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"
                && matches!(&effect.realm, effinterp_proto::ExecutionRealm::Remote { endpoint }
            if endpoint == "backup.host"))
    );
    assert!(
        !p.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete" && effect.realm.is_host())
    );
}

#[test]
fn rsync_local_delete_deletes_dest() {
    let p = plan(&["rsync", "-a", "--delete", "/src/", "/dst/"]);
    assert!(has(&p, "filesystem.read", "/src"));
    assert!(has(&p, "filesystem.write", "/dst"));
    assert!(has(&p, "filesystem.delete", "/dst"));
    let no_traversal = plan(&["rsync", "--delete", "/src/", "/dst/"]);
    assert!(!has_op(&no_traversal, "filesystem.delete"));
}

#[test]
fn scp_from_remote_downloads_and_writes_local() {
    let p = plan(&["scp", "user@server:/etc/config", "/tmp/config"]);
    assert!(p.effects.iter().any(|e| e.operation.0 == "network.download"
        && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "server")));
    assert!(has(&p, "filesystem.write", "/tmp/config"));
}

// --- package managers ---

#[test]
fn apt_install_options_do_not_hide_the_subcommand() {
    for argv in [
        &["apt-get", "install", "-y", "nginx"][..],
        &["apt-get", "-y", "install", "nginx"][..],
    ] {
        let p = plan(argv);
        assert!(has_op(&p, "network.download"), "{argv:?}");
        assert!(has_op(&p, "filesystem.write"), "{argv:?}");
        assert!(
            p.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "package_scripts"),
            "{argv:?}"
        );
    }
}

#[test]
fn pip_uninstall_deletes() {
    let p = plan(&["pip", "uninstall", "requests"]);
    assert!(has_op(&p, "filesystem.delete"));
    assert!(
        p.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "package_scripts")
    );
}

#[test]
fn npm_bare_install_is_an_install() {
    let p = plan(&["npm", "install"]);
    assert!(has_op(&p, "network.download"));
}

#[test]
fn deterministic() {
    let a = effinterp_proto::canonical_json(&plan(&["find", "/x", "-delete"]));
    let b = effinterp_proto::canonical_json(&plan(&["find", "/x", "-delete"]));
    assert_eq!(a, b);
}

#[test]
fn bun_install_add_remove_preserve_dependency_environment_effects() {
    for (argv, operand_index) in [
        (vec!["bun", "install", "left-pad"], 2),
        (vec!["bun", "remove", "left-pad"], 2),
        (vec!["bun", "add", "--dev", "left-pad"], 3),
        (
            vec![
                "bun",
                "add",
                "--registry",
                "https://example.invalid",
                "left-pad",
            ],
            4,
        ),
        (
            vec![
                "bun",
                "add",
                "--registry=https://example.invalid",
                "left-pad",
            ],
            3,
        ),
        (
            vec![
                "bun",
                "add",
                "--dev",
                "--registry",
                "https://example.invalid",
                "--cwd",
                "/work",
                "left-pad",
            ],
            7,
        ),
    ] {
        let plan = effinterp_engine::Engine::new()
            .analyze(&effinterp_proto::Subject::Exec {
                argv: argv.iter().map(|word| (*word).to_string()).collect(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "network.download")
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.write"
                    && matches!(&e.resource,
            effinterp_proto::ResourceExpr::Pattern {pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if pattern == "/work/dependency-tree"))
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "package_scripts")
        );
        for effect in plan.effects.iter().filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "network.download" | "filesystem.write"
            )
        }) {
            assert!(effect.provenance.iter().any(|node| matches!(
                plan.provenance[node.0 as usize].kind,
                effinterp_proto::ProvenanceKind::Argument { index } if index == operand_index
            )));
        }
    }
}
