use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, Effect, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn analyze(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|arg| (*arg).into()).collect(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn deletions(plan: &Plan) -> Vec<&Effect> {
    plan.effects
        .iter()
        .filter(|effect| {
            effect.attributes.get("delete") == Some(&AttrValue::Bool(true))
                && effect.attributes.contains_key("hosted_provider")
        })
        .collect()
}

#[test]
fn hosted_deletions_preserve_kind_target_scope_and_unknown_endpoint() {
    for (argv, provider, kind, object, target, scope) in [
        (
            vec!["gh", "repo", "delete", "owner/repo", "--yes"],
            "github",
            "repository",
            "repository",
            Some("owner/repo"),
            "repository",
        ),
        (
            vec!["gh", "repo", "delete"],
            "github",
            "repository",
            "repository",
            None,
            "repository",
        ),
        (
            vec!["glab", "project", "delete", "group/repo", "-y"],
            "gitlab",
            "repository",
            "repository",
            Some("group/repo"),
            "repository",
        ),
        (
            vec!["glab", "repo", "delete"],
            "gitlab",
            "repository",
            "repository",
            None,
            "repository",
        ),
        (
            vec!["gh", "release", "delete", "v1", "--cleanup-tag", "-y"],
            "github",
            "resource",
            "release",
            Some("v1"),
            "repository",
        ),
        (
            vec!["glab", "release", "delete", "v1", "--with-tag"],
            "gitlab",
            "resource",
            "release",
            Some("v1"),
            "repository",
        ),
        (
            vec!["gh", "secret", "delete", "TOKEN", "--org", "team"],
            "github",
            "resource",
            "secret",
            Some("TOKEN"),
            "organization",
        ),
        (
            vec!["gh", "secret", "remove", "TOKEN", "--user"],
            "github",
            "resource",
            "secret",
            Some("TOKEN"),
            "user",
        ),
        (
            vec![
                "gh",
                "variable",
                "remove",
                "KEY",
                "--env",
                "prod",
                "-R",
                "owner/repo",
            ],
            "github",
            "resource",
            "variable",
            Some("KEY"),
            "environment",
        ),
        (
            vec!["glab", "variable", "delete", "KEY", "--group", "team"],
            "gitlab",
            "resource",
            "variable",
            Some("KEY"),
            "group",
        ),
        (
            vec!["glab", "variable", "remove", "KEY"],
            "gitlab",
            "resource",
            "variable",
            Some("KEY"),
            "repository",
        ),
        (
            vec![
                "gh",
                "cache",
                "delete",
                "cache-key",
                "--ref",
                "refs/heads/main",
            ],
            "github",
            "resource",
            "cache",
            Some("cache-key"),
            "repository",
        ),
        (
            vec!["gh", "cache", "delete", "--all"],
            "github",
            "resource",
            "cache",
            None,
            "repository",
        ),
        (
            vec!["gh", "cache", "delete", "--all", "--succeed-on-no-caches"],
            "github",
            "resource",
            "cache",
            None,
            "repository",
        ),
        (
            vec!["gh", "ssh-key", "delete", "42", "-y"],
            "github",
            "resource",
            "ssh_key",
            Some("42"),
            "user",
        ),
        (
            vec!["glab", "ssh-key", "delete", "42"],
            "gitlab",
            "resource",
            "ssh_key",
            Some("42"),
            "user",
        ),
        (
            vec!["glab", "ssh-key", "delete", "--page", "2"],
            "gitlab",
            "resource",
            "ssh_key",
            None,
            "user",
        ),
    ] {
        let plan = analyze(&argv);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{argv:?}");
        let effect = effects[0];
        let audited_direct = argv.windows(2).any(|pair| {
            matches!(
                pair,
                ["gh", "repo"]
                    | ["gh", "release"]
                    | ["glab", "repo"]
                    | ["glab", "project"]
                    | ["glab", "release"]
                    | ["glab", "ssh-key"]
                    | ["gh", "ssh-key"]
            )
        });
        let exact_delete = audited_direct || matches!(object, "secret" | "cache" | "variable");
        assert_eq!(
            effect.operation.0,
            if exact_delete {
                "network.delete_request"
            } else {
                "network.upload"
            },
            "{argv:?}"
        );
        let confirmed = audited_direct
            && matches!(object, "repository" | "release" | "ssh_key")
            && argv.iter().any(|arg| matches!(*arg, "--yes" | "-y"));
        let must_request = confirmed
            || matches!(object, "secret" | "variable")
            || (object == "cache" && !argv.contains(&"--succeed-on-no-caches"))
            || (object == "ssh_key" && provider == "gitlab" && target.is_some());
        assert_eq!(
            effect.modality,
            if must_request {
                effinterp_proto::Modality::MustOnSuccess
            } else {
                effinterp_proto::Modality::May
            },
            "{argv:?}"
        );
        assert!(
            matches!(&effect.resource, ResourceExpr::Unresolved { family } if family.0 == "network"),
            "{argv:?}: {:?}",
            effect.resource
        );
        for (key, value) in [
            ("method", "DELETE"),
            ("hosted_provider", provider),
            ("hosted_target_kind", kind),
            ("hosted_object_kind", object),
            ("hosted_scope", scope),
        ] {
            assert_eq!(
                effect.attributes.get(key),
                Some(&AttrValue::String(value.into())),
                "{argv:?}: {key}"
            );
        }
        assert_eq!(
            effect.attributes.get("hosted_target"),
            target
                .map(|target| AttrValue::String(target.into()))
                .as_ref(),
            "{argv:?}"
        );
        for (flag, key) in [
            ("--org", "hosted_organization"),
            ("--env", "hosted_environment"),
            ("--scope", "hosted_environment"),
            ("--group", "hosted_group"),
            ("-R", "hosted_repository"),
            ("--ref", "hosted_ref"),
        ] {
            if let Some(index) = argv.iter().position(|arg| *arg == flag) {
                assert_eq!(
                    effect.attributes.get(key),
                    Some(&AttrValue::String(argv[index + 1].into())),
                    "{argv:?}"
                );
            }
        }
    }
}

#[test]
fn hosted_repository_selectors_and_global_overrides_preserve_exact_requests() {
    for target in [
        "github.example.com/owner/project",
        "localhost:9/owner/project",
        "[::1]/owner/project",
        "bücher.invalid/owner/project",
        "bücher.invalid:9/owner/project",
        "[::ffff:127.0.0.1]:9/owner/project",
        "[fe80::1%25lo]:9/owner/project",
        "bu\u{0308}cher.invalid/owner/project",
        "हिन्दी.invalid/owner/project",
        "শক্তি.invalid/owner/project",
        "தமிழ்.invalid/owner/project",
        "ಕನ್ನಡ.invalid/owner/project",
        "శక్తి.invalid/owner/project",
        "[fe80::1%25%6Co]:9/owner/project",
        // The remote-URL forms the selector also takes.
        "https://github.com/owner/project",
        "http://github.example.com/owner/project.git",
        "ssh://git@github.example.com:22/owner/project",
        "git+https://github.example.com/owner/project",
        "git@github.example.com:owner/project.git",
    ] {
        let plan = analyze(&["gh", "repo", "delete", target, "--yes"]);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{target}");
        assert_eq!(
            effects[0].request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{target}"
        );
        assert_eq!(
            effects[0].modality,
            effinterp_proto::Modality::MustOnSuccess,
            "{target}"
        );
    }

    for target in [
        "https://github.com/owner/project/extra",
        "https://github.com/owner",
        "https:///owner/project",
        "ftp://github.example.com/owner/project",
        "git@github.example.com",
        "owner/project/extra/more",
    ] {
        let plan = analyze(&["gh", "repo", "delete", target, "--yes"]);
        assert!(deletions(&plan).is_empty(), "{target}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{target}: {:?}",
            plan.boundaries
        );
    }

    for argv in [
        vec!["gh", "repo", "delete", "owner/project", "--confirm=1"],
        vec!["glab", "repo", "delete", "group/project", "-y=T"],
        vec!["glab", "repo", "delete", "-R", "group/project", "-y"],
        vec![
            "glab",
            "repo",
            "delete",
            "group/project",
            "-yRother/project",
        ],
    ] {
        let plan = analyze(&argv);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{argv:?}");
        assert_eq!(
            effects[0].request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{argv:?}"
        );
        assert_eq!(
            effects[0].modality,
            effinterp_proto::Modality::MustOnSuccess,
            "{argv:?}"
        );
    }
}

#[test]
fn gh_confirmed_symbolic_repository_deletion_keeps_bounded_targets() {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"gh repo delete "$REPOSITORY" --yes"#.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let effects = deletions(&plan);
    assert_eq!(effects.len(), 1);
    assert_eq!(
        effects[0].request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        effects[0].modality,
        effinterp_proto::Modality::MustOnSuccess
    );
    let ResourceExpr::Union { alternatives } = &effects[0].resource else {
        panic!("unexpected repository targets: {:?}", effects[0].resource);
    };
    assert!(alternatives.iter().any(
        |target| matches!(target, ResourceExpr::Environment { name } if name == "REPOSITORY")
    ));
    assert!(alternatives.iter().any(|target| matches!(
        target,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, path: None, .. }
        } if host == "github.com"
    )));
    assert!(plan.boundaries.iter().all(|boundary| {
        boundary.reason.as_str() != "unrecognized_arguments"
            || !boundary.domains.iter().any(|domain| domain.0 == "network")
    }));

    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"gh repo delete "$REPOSITORY" --yes"#.into(),
            cwd: Some("/work".into()),
            context: HostContext {
                env_unset: ["REPOSITORY".into()].into_iter().collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();

    let effects = deletions(&plan);
    assert_eq!(effects.len(), 1);
    assert_eq!(
        effects[0].request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        effects[0].modality,
        effinterp_proto::Modality::MustOnSuccess
    );
    assert!(matches!(
        &effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, path: None, .. }
        } if host == "github.com"
    ));
    assert!(plan.boundaries.iter().all(|boundary| {
        boundary.reason.as_str() != "unrecognized_arguments"
            || !boundary.domains.iter().any(|domain| domain.0 == "network")
    }));

    let unconfirmed = analyze(&["gh", "repo", "delete", ""]);
    assert!(unconfirmed.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unrecognized_arguments"
            && boundary.domains.iter().any(|domain| domain.0 == "network")
    }));
}

#[test]
fn hosted_negative_controls_do_not_claim_deletion() {
    let long_key = "A".repeat(256);
    for argv in [
        vec![
            "gh",
            "api",
            "-h=false",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec!["glab", "variable", "delete", &long_key],
        vec!["gh", "release", "delete", "v1", "--repo", "bare-name"],
        vec!["glab", "ssh-key", "delete", "42", "--page", "08"],
        vec!["gh", "repo", "delete", ""],
        vec!["gh", "repo", "delete", "owner//repo"],
        vec!["gh", "repo", "delete", "host/owner/repo/extra"],
        vec![
            "gh",
            "repo",
            "delete",
            "localhost:65536/owner/repo",
            "--yes",
        ],
        vec!["gh", "repo", "delete", "[::1/owner/repo", "--yes"],
        vec![
            "gh",
            "repo",
            "delete",
            "[fe80::1%25%ZZ]/owner/repo",
            "--yes",
        ],
        vec!["glab", "repo", "delete", ""],
        vec!["glab", "repo", "delete", "group//repo"],
        vec!["gh", "release", "delete", ""],
        vec!["gh", "release", "delete", "bad tag"],
        vec!["gh", "release", "delete", "v1..2"],
        vec!["glab", "release", "delete", "v1.lock"],
        vec!["glab", "release", "delete", ""],
        vec!["gh", "secret", "delete", ""],
        vec!["gh", "variable", "delete", "KEY", "--env="],
        vec!["gh", "secret", "delete", "KEY", "--org="],
        vec!["glab", "variable", "delete", ""],
        vec!["glab", "variable", "delete", "invalid-key"],
        vec![
            "glab", "variable", "delete", "KEY", "--group", "team", "--scope", "prod",
        ],
        vec!["gh", "cache", "delete", ""],
        vec!["gh", "cache", "delete", "42", "--ref", "refs/heads/main"],
        vec!["gh", "cache", "delete", "+42", "--ref", "refs/heads/main"],
        vec!["gh", "ssh-key", "delete", ""],
        vec!["gh", "ssh-key", "delete", "invalid"],
        vec!["gh", "ssh-key", "delete", "0"],
        vec!["glab", "ssh-key", "delete", "--", "-1"],
        vec!["glab", "ssh-key", "delete", ""],
        vec!["glab", "ssh-key", "delete", "invalid"],
        vec!["glab", "ssh-key", "delete", "42", "--page", "invalid"],
        vec!["gh", "release", "delete", "v1", "--repo", "owner/"],
        vec!["gh", "repo", "delete", "owner/repo", "--help"],
        vec!["glab", "project", "delete", "group/repo", "-h"],
        vec!["gh", "repo", "delete", "owner/repo", "--dry-run"],
        vec!["gh", "repo", "delete", "owner/repo", "--cleanup-tag=false"],
        vec!["gh", "repo", "delete", "owner/repo", "-y=maybe"],
        vec!["gh", "release", "delete", "v1", "--all=false"],
        vec!["glab", "repo", "delete", "group/repo", "--with-tag=false"],
        vec!["gh", "cache", "delete", "key", "--user=false"],
        vec!["glab", "release", "delete", "v1", "--unknown"],
        vec!["gh", "release", "delete"],
        vec!["gh", "repo", "delete", "first", "second"],
        vec![
            "gh", "secret", "delete", "KEY", "--org", "team", "--env", "prod",
        ],
        vec!["gh", "secret", "delete", "KEY", "--app", "unknown"],
        vec![
            "gh", "secret", "delete", "KEY", "--user", "--app", "actions",
        ],
        vec!["gh", "secret", "delete", "KEY", "--org"],
        vec!["gh", "cache", "delete"],
        vec!["gh", "cache", "delete", "--all=false"],
        vec!["gh", "cache", "delete", "key", "--all"],
        vec!["gh", "cache", "delete", "key", "--succeed-on-no-caches"],
        vec!["glab", "secret", "delete", "KEY"],
        vec!["glab", "cache", "delete", "--all"],
        vec!["gh", "project", "delete", "1"],
        vec![
            "gh",
            "repo",
            "delete",
            "owner/repo",
            "--repo",
            "another/repo",
        ],
        vec!["gh", "cache", "delete", "-a"],
        vec!["gh", "secret", "delete", "KEY", "-a", "actions"],
    ] {
        let plan = analyze(&argv);
        assert!(deletions(&plan).is_empty(), "{argv:?}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "artifact.delete"),
            "{argv:?}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "network.upload"),
            "{argv:?}"
        );
    }
    for source in [
        r#"gh repo delete "$TARGET""#,
        r#"gh repo delete owner/repo --yes="$CONFIRM""#,
        r#"gh release delete "$TAG" --yes"#,
        r#"gh release delete v1 --cleanup-tag="$CLEANUP""#,
        r#"gh secret delete "$NAME" --org team"#,
        r#"glab project delete "$PROJECT" --yes"#,
        r#"glab variable delete KEY --scope "$SCOPE""#,
        r#"gh cache delete --all="$ALL""#,
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(deletions(&plan).is_empty(), "{source}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "network.upload"),
            "{source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{source}"
        );
    }
    let plan = analyze(&[
        "gh",
        "release",
        "delete",
        "v1",
        "--yes",
        "--yes=false",
        "--cleanup-tag",
        "--cleanup-tag=false",
        "--help=false",
    ]);
    let effects = deletions(&plan);
    assert_eq!(effects.len(), 1);
    for key in ["confirmation_requested", "cleanup_tag"] {
        assert_eq!(
            effects[0].attributes.get(key),
            Some(&AttrValue::Bool(false)),
            "{key}"
        );
    }
    let plan = analyze(&["gh", "cache", "delete", "--all=false", "--all"]);
    let effects = deletions(&plan);
    assert_eq!(effects.len(), 1);
    assert_eq!(
        effects[0].attributes.get("all"),
        Some(&AttrValue::Bool(true))
    );
}

#[test]
fn hosted_api_delete_routes_keep_repository_and_resource_identity_distinct() {
    for hostname in [
        "localhost",
        "ghe.example",
        "GHE-1.example.",
        "127.0.0.1",
        "bücher.example",
        "bu\u{0308}cher.example",
        "हिन्दी.example",
        "শক্তি.example",
        "தமிழ்.example",
        "ಕನ್ನಡ.example",
        "శక్తి.example",
    ] {
        let plan = analyze(&[
            "gh",
            "api",
            "--hostname",
            hostname,
            "-X",
            "DELETE",
            "repos/owner/project",
        ]);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{hostname}");
        assert_eq!(
            effects[0].modality,
            effinterp_proto::Modality::MustOnSuccess
        );
        assert_eq!(
            effects[0].request_assurance,
            effinterp_proto::RequestAssurance::Exact
        );
    }
    for (argv, provider, target_kind, object_kind) in [
        (
            vec!["gh", "api", "-X", "DELETE", "repos/owner/project"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "-X", "DELETE", "/repos/owner/project"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec![
                "gh",
                "api",
                "--hostname",
                "ghe.example",
                "--silent",
                "--method=delete",
                "repos/owner/project?audit=true",
            ],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "-X", "DELETE", "repos/owner/project#/issues"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "-iXDELETE", "repos/owner/project"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "-i=false", "-XDELETE", "repos/owner/project"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "-iiX", "DELETE", "repos/owner/project"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec![
                "gh",
                "api",
                "-ip",
                "corsair",
                "-X",
                "DELETE",
                "repos/owner/project",
            ],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "--method=delete", "repos/{owner}/{repo}"],
            "github",
            "repository",
            "repository",
        ),
        (
            vec![
                "gh",
                "api",
                "--hostname",
                "ghe.example",
                "--silent",
                "--method=delete",
                "repos/owner/project",
            ],
            "github",
            "repository",
            "repository",
        ),
        (
            vec![
                "gh",
                "api",
                "--paginate=false",
                "-X",
                "DELETE",
                "repos/owner/project",
            ],
            "github",
            "repository",
            "repository",
        ),
        (
            vec!["gh", "api", "-X", "DELETE", "repos/owner/project/hooks/123"],
            "github",
            "resource",
            "api_resource",
        ),
        (
            vec!["gh", "api", "-X", "DELETE", "gists/0123456789abcdef"],
            "github",
            "resource",
            "api_resource",
        ),
        (
            vec!["glab", "api", "projects/123", "-X", "DELETE"],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec!["glab", "api", "-X", "DELETE", "/projects/123"],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec![
                "glab",
                "api",
                "--method",
                "DELETE",
                "/projects/group%2Fproject?hard_delete=true",
            ],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec!["glab", "api", "-X", "DELETE", "projects/123#anything"],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec!["glab", "api", "-X", "DELETE", "projects/:namespace/:repo"],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec![
                "glab",
                "api",
                "-X",
                "DELETE",
                "projects/:group/:namespace/:repo",
            ],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec!["glab", "api", "-iXDELETE", "projects/123"],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec![
                "glab",
                "api",
                "-iRother/project",
                "-X",
                "DELETE",
                "projects/123",
            ],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec!["glab", "api", "--silent", "-X", "DELETE", "projects/123"],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec![
                "glab",
                "api",
                "--method",
                "DELETE",
                "projects/group%2Fproject",
            ],
            "gitlab",
            "repository",
            "repository",
        ),
        (
            vec![
                "glab",
                "api",
                "-X",
                "DELETE",
                "projects/123/variables/DEPLOY_ENV",
            ],
            "gitlab",
            "resource",
            "api_resource",
        ),
    ] {
        let plan = analyze(&argv);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{argv:?}");
        let effect = effects[0];
        assert_eq!(effect.operation.0, "network.delete_request");
        assert_eq!(
            effect.modality,
            effinterp_proto::Modality::MustOnSuccess,
            "{argv:?}"
        );
        assert_eq!(
            effect.attributes.get("method"),
            Some(&AttrValue::String("DELETE".into())),
            "{argv:?}"
        );
        for (key, value) in [
            ("hosted_provider", provider),
            ("hosted_target_kind", target_kind),
            ("hosted_object_kind", object_kind),
        ] {
            assert_eq!(
                effect.attributes.get(key),
                Some(&AttrValue::String(value.into())),
                "{argv:?}: {key}"
            );
        }
    }
    for template in [
        "}}",
        "{{.name}}",
        "{{\"literal\"}}",
        "{{$item := .}}{{$item}}",
        "{{$é := .}}{{$é}}",
        "{{printf \"%c\" 'a'}}",
        "{{replace \"a\" \"b\" \"a\"}}",
        "{{range $i, $v := .}}{{$v}}{{end}}",
        "{{range .}}{{break}}{{end}}",
        "{{1_000}}",
        "{{0x1.fp2}}",
        "{{1+2i}}",
    ] {
        let plan = analyze(&[
            "gh",
            "api",
            "--template",
            template,
            "-X",
            "DELETE",
            "repos/owner/project",
        ]);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{template}");
        assert_eq!(
            effects[0].request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{template}"
        );
    }
    for argv in [
        [
            "gh",
            "api",
            "-F",
            "ref={branch}",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        [
            "glab",
            "api",
            "-F",
            "audit=true",
            "-X",
            "DELETE",
            "projects/123",
        ],
        [
            "glab",
            "api",
            "-F",
            "data=[1,true,\"audit\"]",
            "-X",
            "DELETE",
            "projects/123",
        ],
        [
            "glab",
            "api",
            "-F",
            "data=null",
            "-X",
            "DELETE",
            "projects/123",
        ],
        [
            "glab",
            "api",
            "-f",
            "data={\"audit\":true}",
            "-X",
            "DELETE",
            "projects/123",
        ],
    ] {
        assert_eq!(deletions(&analyze(&argv)).len(), 1, "{argv:?}");
    }
}

#[test]
fn hosted_api_delete_routes_distinguish_assurance_and_reject_invalid_controls() {
    for hostname in [
        "",
        "bad#host",
        "bad host",
        "bad:443",
        "bad@host",
        "bad?host",
        "bad..host",
        "\u{200d}.example",
    ] {
        let plan = analyze(&[
            "gh",
            "api",
            "--hostname",
            hostname,
            "-X",
            "DELETE",
            "repos/owner/project",
        ]);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("network.")),
            "{hostname}"
        );
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unrecognized_arguments"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("hostname"))
            }),
            "{hostname}"
        );
    }
    // A hostname holding a slash is refused while the flags are validated, so
    // there is no request to route and nothing left unresolved.
    for hostname in ["bad/host", "bad/host/extra"] {
        let plan = analyze(&[
            "gh",
            "api",
            "--hostname",
            hostname,
            "-X",
            "DELETE",
            "repos/owner/project",
        ]);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("network.")),
            "{hostname}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{hostname}: {:?}",
            plan.boundaries
        );
    }
    for argv in [
        vec!["gh", "api", "-X", "DELETE", "repos/owner/project/issues/42"],
        vec!["glab", "api", "-X", "DELETE", "projects/group/project"],
    ] {
        let plan = analyze(&argv);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{argv:?}");
        assert_eq!(
            effects[0].request_assurance,
            effinterp_proto::RequestAssurance::Conservative,
            "{argv:?}"
        );
    }
    for argv in [
        vec![
            "gh",
            "api",
            "--paginate",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec!["glab", "api", "--paginate", "-X", "DELETE", "projects/123"],
        vec![
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "glab",
            "api",
            "-H",
            "Content-Length: 0",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "--output",
            "ndjson",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "--paginate=false",
            "--input",
            "/dev/null",
            "-X",
            "DELETE",
            "projects/123",
        ],
        // An empty field name is a query parameter glab sends like any other.
        vec![
            "glab",
            "api",
            "-F",
            "=value",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "gh",
            "api",
            "-f",
            "a=1",
            "-f",
            "a=2",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
    ] {
        let plan = analyze(&argv);
        let effects = deletions(&plan);
        assert_eq!(effects.len(), 1, "{argv:?}");
        assert_eq!(
            effects[0].request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{argv:?}"
        );
    }
    // Options the tool refuses while validating flags: no request is made, and
    // nothing about the invocation is left unresolved.
    for argv in [
        // Standard input is one stream, so a second form field reading it is
        // refused before any part of the body is written.
        vec![
            "glab",
            "api",
            "--form",
            "first=@-",
            "--form",
            "second=@-",
            "-X",
            "DELETE",
            "projects/123",
        ],
        // A field value the command reads as JSON and cannot: it never reaches
        // the request. An object, a nested array, a null element and two names
        // addressing one parameter have no query-string rendering, so a query
        // method refuses those too.
        vec![
            "glab",
            "api",
            "-F",
            "data={",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "-F",
            "data={\"audit\":true}",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "-F",
            "data=[null]",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "-F",
            "data=[[1]]",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "-F",
            "data=[{\"audit\":true}]",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "-f",
            "ids[]=1",
            "-F",
            "ids=[2,3]",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "gh",
            "api",
            "--slurp",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "--hostname",
            "bad/host",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "glab",
            "api",
            "--output",
            "yaml",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "--form",
            "a=b",
            "--field",
            "c=d",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "--paginate",
            "--input",
            "body.json",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "gh",
            "api",
            "--header",
            ": value",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "glab",
            "api",
            "-H",
            "invalid",
            "-X",
            "DELETE",
            "projects/123",
        ],
        vec![
            "glab",
            "api",
            "-H",
            "Content-Length:nope",
            "-X",
            "DELETE",
            "projects/123",
        ],
        // pflag refuses an option value it cannot parse, and an option the
        // command does not define at all.
        vec![
            "gh",
            "api",
            "-i=maybe",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "-h=false",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec!["gh", "issue", "delete", "42", "--unknown"],
        vec![
            "gh",
            "api",
            "--silent",
            "--verbose",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "--jq",
            ".name",
            "--silent",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "--cache",
            "invalid",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "--cache",
            "5",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "--cache",
            "1h.",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        // A literal "*" carries no colon, so it is refused like any other
        // malformed field line; the shell-expanded form stays a boundary
        // because the value is not decided here.
        vec![
            "gh",
            "api",
            "-X",
            "DELETE",
            "repos/owner/project",
            "--header",
            "*",
        ],
    ] {
        let plan = analyze(&argv);
        assert!(deletions(&plan).is_empty(), "{argv:?}");
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
    for template in [
        "{{break}}",
        "{{08}}",
        "{{else}}",
        "{{. | unknownfunc}}",
        "{{. |}}",
        "{{0x}}",
        "{{1__2}}",
        "{{(.)}}",
        "{{printf (.}}",
        "{{$missing}}",
        "{{printf \"%s\" \"\\/\"}}",
        "{{printf \"%s\" \"\\uD800\\uDC00\"}}",
        "{{'\n'}}",
        "{{18446744073709551616}}",
        "{{0x1.fp9999999}}",
        "{{\u{a0}.\u{a0}}}",
        "{{\u{b}.\u{b}}}",
    ] {
        let plan = analyze(&[
            "gh",
            "api",
            "--template",
            template,
            "-X",
            "DELETE",
            "repos/owner/project",
        ]);
        assert!(deletions(&plan).is_empty(), "{template}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{template}: {:?}",
            plan.boundaries
        );
    }
    // gh rejects a field without a `key=` separator before sending, unless
    // its last key component is empty.
    for fields in [
        &["-f", "invalid"][..],
        &["-F", "invalid"],
        &["-F", "a[b]"],
        &["-F", "a.b"],
    ] {
        let mut argv = vec!["gh", "api"];
        argv.extend(fields);
        argv.extend(["-X", "DELETE", "repos/owner/project"]);
        let plan = analyze(&argv);
        assert!(deletions(&plan).is_empty(), "{argv:?}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
    // A field whose last key component is empty (`a[]`) is an empty array
    // and needs no value, so the DELETE is still sent.
    for fields in [
        &["-f", "a[]"][..],
        &["-F", "a[]"],
        &["-F", "a[b][]"],
        &["-F", "[]"],
    ] {
        let mut argv = vec!["gh", "api"];
        argv.extend(fields);
        argv.extend(["-X", "DELETE", "repos/owner/project"]);
        let plan = analyze(&argv);
        assert!(!deletions(&plan).is_empty(), "{argv:?}");
    }
    for source in [
        r#"gh api -X DELETE "$ENDPOINT""#,
        r#"glab api --method "$METHOD" projects/123"#,
        r#"gh api --hostname "$HOST" -X DELETE repos/owner/project"#,
        r#"glab api -F "data=$VALUE" -X DELETE projects/123"#,
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(deletions(&plan).is_empty(), "{source}");
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unrecognized_arguments"
                && boundary.class == effinterp_proto::BoundaryClass::Unresolved
        }));
    }
}

#[test]
fn confirmed_hosted_deletes_require_effective_confirmation_and_complete_grammar() {
    use effinterp_proto::{Modality, RequestAssurance};

    for prefix in [
        vec!["gh", "repo", "delete", "owner/repo"],
        vec!["gh", "release", "delete", "v1"],
        vec!["glab", "project", "delete", "group/repo"],
        vec!["glab", "release", "delete", "v1"],
    ] {
        for (suffix, must) in [
            (vec![], false),
            (vec!["--yes"], true),
            (vec!["--yes=true"], true),
            (vec!["--yes=false"], false),
            (vec!["--yes", "--yes=false"], false),
            (vec!["--yes=false", "--yes"], true),
        ] {
            let argv: Vec<_> = prefix.iter().chain(&suffix).copied().collect();
            let plan = analyze(&argv);
            let requests = deletions(&plan);
            assert_eq!(requests.len(), 1, "{argv:?}");
            assert_eq!(requests[0].operation.0, "network.delete_request");
            assert_eq!(requests[0].request_assurance, RequestAssurance::Exact);
            assert_eq!(
                requests[0].modality,
                if must {
                    Modality::MustOnSuccess
                } else {
                    Modality::May
                },
                "{argv:?}"
            );
            assert!(matches!(
                requests[0].resource,
                ResourceExpr::Unresolved { .. }
            ));
        }
        for suffix in [
            vec!["--yes", "--help"],
            vec!["--yes", "--dry-run"],
            vec!["--yes", "--unknown"],
            vec!["--yes=invalid"],
            vec!["--yes", "extra"],
        ] {
            let argv: Vec<_> = prefix.iter().chain(&suffix).copied().collect();
            assert!(deletions(&analyze(&argv)).is_empty(), "{argv:?}");
        }
    }
    for argv in [
        vec!["gh", "repo", "delete", "--yes"],
        vec!["gh", "repo", "delete"],
    ] {
        let plan = analyze(&argv);
        assert_eq!(deletions(&plan)[0].modality, Modality::May, "{argv:?}");
    }
    for argv in [
        vec!["gh", "release", "delete", "v1", "-y"],
        vec!["glab", "repo", "delete", "-y"],
        vec!["glab", "release", "delete", "v1", "-y"],
    ] {
        let plan = analyze(&argv);
        assert_eq!(
            deletions(&plan)[0].modality,
            Modality::MustOnSuccess,
            "{argv:?}"
        );
    }
    let conditional = Engine::new()
        .analyze(&Subject::Shell {
            source: "test -e marker && gh repo delete owner/repo --yes".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&conditional).unwrap();
    assert!(
        deletions(&conditional)
            .iter()
            .all(|effect| effect.condition.is_some())
    );
}

fn exact_deletion(argv: &[&str], kind: &str, modality: effinterp_proto::Modality) {
    let plan = analyze(argv);
    let effects = deletions(&plan);
    assert_eq!(effects.len(), 1, "{argv:?}: {:?}", plan.boundaries);
    assert_eq!(effects[0].operation.0, "network.delete_request", "{argv:?}");
    assert_eq!(
        effects[0].request_assurance,
        effinterp_proto::RequestAssurance::Exact,
        "{argv:?}"
    );
    assert_eq!(effects[0].modality, modality, "{argv:?}");
    assert_eq!(
        effects[0].attributes.get("hosted_target_kind"),
        Some(&AttrValue::String(kind.into())),
        "{argv:?}"
    );
}

#[test]
fn api_method_last_occurrence_selects_the_request() {
    use effinterp_proto::Modality::MustOnSuccess;

    for argv in [
        vec![
            "gh",
            "api",
            "--method",
            "GET",
            "-X",
            "DELETE",
            "repos/owner/project",
        ],
        vec![
            "gh",
            "api",
            "-iiiX",
            "GET",
            "-XDELETE",
            "repos/owner/project",
        ],
        vec![
            "glab",
            "api",
            "-X",
            "GET",
            "--method",
            "DELETE",
            "projects/123",
        ],
    ] {
        exact_deletion(&argv, "repository", MustOnSuccess);
    }
    for argv in [
        vec![
            "gh",
            "api",
            "-X",
            "DELETE",
            "--method",
            "GET",
            "repos/owner/project",
        ],
        vec!["glab", "api", "-X", "DELETE", "-X", "GET", "projects/123"],
    ] {
        assert!(deletions(&analyze(&argv)).is_empty(), "{argv:?}");
    }
}

#[test]
fn api_resource_delete_routes_are_exact() {
    use effinterp_proto::Modality::MustOnSuccess;

    for route in [
        "repos/owner/project/keys/123",
        "repos/owner/project/actions/secrets/DEPLOY_TOKEN",
        "repos/owner/project/actions/variables/API_ORIGIN",
        "repos/owner/project/environments/production",
        "user/keys/123",
    ] {
        exact_deletion(
            &["gh", "api", "-X", "DELETE", route],
            "resource",
            MustOnSuccess,
        );
    }
    for route in [
        "projects/123/releases/v1.2.3",
        "projects/group%2Fproject/hooks/123",
        "projects/123/protected_branches/main",
        "/projects/123/deploy_keys/456",
    ] {
        exact_deletion(
            &["glab", "api", "-X", "DELETE", route],
            "resource",
            MustOnSuccess,
        );
    }
    // A key route needs a numeric id; anything else stays a conservative request.
    let plan = analyze(&["gh", "api", "-X", "DELETE", "user/keys/latest"]);
    assert_eq!(
        deletions(&plan)[0].request_assurance,
        effinterp_proto::RequestAssurance::Conservative
    );
}

#[test]
fn prompted_verb_deletions_are_guaranteed_only_when_confirmed() {
    use effinterp_proto::Modality::{May, MustOnSuccess};

    for (prefix, object) in [
        (vec!["gh", "gist", "delete", "0123456789abcdef"], "gist"),
        (
            vec!["gh", "gpg-key", "delete", "3AA5C34371567BD2"],
            "gpg_key",
        ),
        (
            vec!["gh", "issue", "delete", "42", "-R", "owner/project"],
            "issue",
        ),
        (vec!["gh", "ssh-key", "delete", "42"], "ssh_key"),
    ] {
        for (suffix, modality) in [
            (vec!["--yes"], MustOnSuccess),
            (vec!["--yes=false"], May),
            (vec![], May),
        ] {
            let argv: Vec<_> = prefix.iter().chain(&suffix).copied().collect();
            exact_deletion(&argv, "resource", modality);
            assert_eq!(
                deletions(&analyze(&argv))[0]
                    .attributes
                    .get("hosted_object_kind"),
                Some(&AttrValue::String(object.into())),
                "{argv:?}"
            );
        }
    }
    // gh gist delete has no -y shorthand, so it never confirms the deletion.
    let plan = analyze(&["gh", "gist", "delete", "0123456789abcdef", "-y"]);
    assert!(deletions(&plan).is_empty());
    // With no selector gh gist delete picks the gist interactively.
    exact_deletion(&["gh", "gist", "delete", "--yes"], "resource", May);
}

#[test]
fn unprompted_verb_deletions_are_guaranteed() {
    use effinterp_proto::Modality::MustOnSuccess;

    for argv in [
        vec!["gh", "variable", "delete", "API_ORIGIN", "--org", "example"],
        vec![
            "gh",
            "repo",
            "deploy-key",
            "delete",
            "789",
            "-R",
            "owner/project",
        ],
        vec![
            "glab",
            "variable",
            "delete",
            "DEPLOY_ENV",
            "--scope",
            "production",
        ],
        vec!["glab", "variable", "remove", "GROUP_TOKEN", "-g", "example"],
        vec!["glab", "deploy-key", "delete", "456", "-R", "group/project"],
    ] {
        exact_deletion(&argv, "resource", MustOnSuccess);
    }
    for argv in [
        vec!["gh", "repo", "deploy-key", "delete", "latest"],
        vec!["glab", "deploy-key", "delete", "latest"],
    ] {
        let plan = analyze(&argv);
        assert!(deletions(&plan).is_empty(), "{argv:?}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{argv:?}"
        );
    }
}

#[test]
fn bare_repository_name_resolves_against_the_signed_in_owner() {
    use effinterp_proto::Modality::{May, MustOnSuccess};

    exact_deletion(&["gh", "repo", "delete", "project"], "repository", May);
    exact_deletion(
        &["gh", "repo", "delete", "my.project-1_x", "--yes"],
        "repository",
        MustOnSuccess,
    );
    let plan = analyze(&["gh", "repo", "delete", "..", "--yes"]);
    assert!(deletions(&plan).is_empty());
    assert!(!plan.boundaries.is_empty());
}

#[test]
fn api_form_fields_keep_the_delete_request() {
    use effinterp_proto::Modality::MustOnSuccess;

    for form in [
        vec!["--form", "a=b"],
        vec!["--form", "body=@-", "--form", "c=d"],
    ] {
        let argv: Vec<_> = ["glab", "api"]
            .into_iter()
            .chain(form)
            .chain(["-X", "DELETE", "projects/123"])
            .collect();
        exact_deletion(&argv, "repository", MustOnSuccess);
    }
    // A field without '=' breaks the multipart body, and glab refuses a
    // second field reading standard input.
    for form in [
        vec!["--form", "a"],
        vec!["--form", "a=@-", "--form", "b=@-"],
    ] {
        let argv: Vec<_> = ["glab", "api"]
            .into_iter()
            .chain(form)
            .chain(["-X", "DELETE", "projects/123"])
            .collect();
        assert!(deletions(&analyze(&argv)).is_empty(), "{argv:?}");
    }
}

#[test]
fn hosted_ref_writes_state_the_push_they_request() {
    fn push_requests(plan: &Plan) -> Vec<&Effect> {
        plan.effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "git.push_request")
            .collect()
    }
    let flag = |effect: &Effect, key: &str| match effect.attributes.get(key) {
        Some(AttrValue::Bool(value)) => Some(*value),
        _ => None,
    };
    // (argv, exact, explicit force, deleted, destination)
    for (argv, exact, force, deleted, destination) in [
        (
            &[
                "gh",
                "api",
                "-iXPATCH",
                "repos/o/r/git/refs/heads/main",
                "-f",
                "sha=abc",
                "-F",
                "force=true",
            ][..],
            true,
            Some(true),
            Some(false),
            Some("main"),
        ),
        (
            &[
                "gh",
                "api",
                "--method",
                "DELETE",
                "repos/o/r/git/refs/tags/v1",
            ],
            true,
            Some(false),
            Some(true),
            Some("refs/tags/v1"),
        ),
        // A string `force` or a body from `--input` may still force.
        (
            &[
                "gh",
                "api",
                "-X",
                "PATCH",
                "repos/o/r/git/refs/heads/main",
                "-f",
                "force=true",
            ],
            false,
            None,
            Some(false),
            Some("main"),
        ),
        (
            &[
                "gh",
                "api",
                "-X",
                "PATCH",
                "repos/o/r/git/refs/heads/main",
                "--input",
                "body.json",
                "-F",
                "force=false",
            ],
            false,
            None,
            Some(false),
            Some("main"),
        ),
        (
            &[
                "gh",
                "api",
                "-X",
                "PATCH",
                "repos/o/r/git/refs/heads/main?x=1",
                "-F",
                "force=true",
            ],
            false,
            Some(true),
            Some(false),
            None,
        ),
        // gh's option parser strips `=` after a short option.
        (
            &["gh", "api", "-X=DELETE", "repos/o/r/git/refs/heads/old"],
            true,
            Some(false),
            Some(true),
            Some("old"),
        ),
        (
            &[
                "gh",
                "api",
                "-X",
                "PATCH",
                "repos/o/r/git/refs/heads/main",
                "-F=force=true",
            ],
            true,
            Some(true),
            Some(false),
            Some("main"),
        ),
        // A fast-forward update is a non-forced push, which the
        // protected-branch guard still decides. An empty `--input` names no
        // body, so the fields still state `force`.
        (
            &[
                "gh",
                "api",
                "-iX=PATCH",
                "repos/o/r/git/refs/heads/main",
                "-F=force=false",
            ],
            true,
            Some(false),
            Some(false),
            Some("main"),
        ),
        (
            &[
                "gh",
                "api",
                "-X",
                "PATCH",
                "repos/o/r/git/refs/heads/main",
                "-f",
                "sha=abc",
            ],
            true,
            Some(false),
            Some(false),
            Some("main"),
        ),
        (
            &[
                "gh",
                "api",
                "-X",
                "PATCH",
                "repos/o/r/git/refs/heads/main",
                "-F",
                "force=false",
                "--input",
                "body.json",
                "--input=",
            ],
            true,
            Some(false),
            Some(false),
            Some("main"),
        ),
        // gh sends an absolute URL as written: GitHub's REST root, or the
        // Enterprise root of the `--hostname` host.
        (
            &[
                "gh",
                "api",
                "-X",
                "DELETE",
                "https://api.github.com/repos/o/r/git/refs/heads/old",
            ],
            true,
            Some(false),
            Some(true),
            Some("old"),
        ),
        (
            &[
                "gh",
                "api",
                "--hostname",
                "ghe.example",
                "-X",
                "PATCH",
                "https://ghe.example/api/v3/repos/o/r/git/refs/heads/main",
                "-F",
                "force=true",
            ],
            true,
            Some(true),
            Some(false),
            Some("main"),
        ),
        // A remote fork syncs through the API. Its forced reset only follows
        // a failed merge-upstream, so the request is `may`.
        (
            &["gh", "repo", "sync", "owner/fork", "--force", "-b", "main"],
            true,
            Some(true),
            Some(false),
            Some("main"),
        ),
    ] {
        let plan = analyze(argv);
        let requests = push_requests(&plan);
        let [request] = requests.as_slice() else {
            panic!("{argv:?}: {requests:?}");
        };
        assert_eq!(
            request.request_assurance == effinterp_proto::RequestAssurance::Exact,
            exact,
            "{argv:?}"
        );
        assert_eq!(flag(request, "explicit_force"), force, "{argv:?}");
        // A ref write joins its one destination, named as a push names it,
        // to whether it is deleted. The declarative `gh repo sync` model
        // states its branch as `destination_0`.
        if argv[1] == "api" {
            assert_eq!(
                request.attributes.get("deleted_destinations"),
                destination
                    .zip(deleted)
                    .map(|(name, deleted)| AttrValue::List(if deleted {
                        vec![AttrValue::String(name.into())]
                    } else {
                        vec![]
                    }))
                    .as_ref(),
                "{argv:?}"
            );
        } else {
            assert_eq!(flag(request, "deleted_0"), deleted, "{argv:?}");
            assert_eq!(
                request.attributes.get("destination_0"),
                destination
                    .map(|value| AttrValue::String(value.into()))
                    .as_ref(),
                "{argv:?}"
            );
        }
        assert_eq!(
            plan.boundaries.is_empty(),
            exact && destination.is_some(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
    // A read, another route, a URL on a host that is not a GitHub API root,
    // a sync without force and the local sync request no remote push.
    for argv in [
        &["gh", "api", "repos/o/r/git/refs/heads/main"][..],
        &[
            "gh",
            "api",
            "-X",
            "PATCH",
            "repos/o/r/pulls/1",
            "-F",
            "force=true",
        ],
        &[
            "gh",
            "api",
            "-X",
            "DELETE",
            "https://evil.example/repos/o/r/git/refs/heads/old",
        ],
        &[
            "gh",
            "api",
            "-X",
            "DELETE",
            "https://ghe.example/api/v3/repos/o/r/git/refs/heads/old",
        ],
        &["gh", "repo", "sync", "owner/fork"],
        &["gh", "repo", "sync", "--force"],
    ] {
        let plan = analyze(argv);
        assert!(push_requests(&plan).is_empty(), "{argv:?}");
    }
    // The local forced sync hard-resets the checked-out branch when it is the
    // synced branch and has diverged; gh's dirty check can miss untracked
    // files, so the reset stays possible and unresolved.
    let plan = analyze(&["gh", "repo", "sync", "--force"]);
    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "git.reset_request"
                && effect.attributes.get("reset_mode") == Some(&AttrValue::String("hard".into()))
        }),
        "{:?}",
        plan.effects
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.domains.iter().any(|domain| domain.0 == "git")),
        "{:?}",
        plan.boundaries
    );
}
