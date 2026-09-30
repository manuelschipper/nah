use effinterp_proto::{
    PathPlatform, ResourceExpr, ResourceFamily, ResourceIdentity, display_identity, normalize_path,
    normalize_resource,
};
use effinterp_repo::{DatabaseIdentitySelector, GitIdentitySelector, identity_from_selector};

use crate::typed_selector;

#[test]
fn path_normalization_is_platform_explicit_and_idempotent() {
    assert_eq!(
        normalize_path("/srv//app/../data", PathPlatform::Posix),
        "/srv/data"
    );
    assert_eq!(
        normalize_path(r"c:\work\.\app\..\data", PathPlatform::Windows),
        "C:/work/data"
    );
    assert_eq!(normalize_path(".", PathPlatform::Posix), ".");
    assert_eq!(normalize_path("", PathPlatform::Posix), ".");
    assert_eq!(normalize_path("./", PathPlatform::Posix), ".");
    assert_eq!(normalize_path("a/..", PathPlatform::Posix), ".");
    for input in [
        "./C:./",
        "./C:./b/c",
        r".\C:.\b\c",
        "a/../c:",
        "x/y/../../d:",
        ".//c:",
    ] {
        let once = normalize_path(input, PathPlatform::Windows);
        assert_eq!(
            normalize_path(&once, PathPlatform::Windows),
            once,
            "{input}"
        );
    }
    assert_eq!(normalize_path("./C:./", PathPlatform::Windows), "C:");
    assert_eq!(normalize_path("./C:./b/c", PathPlatform::Windows), "C:b/c");
    let once = normalize_resource(path("/srv//app/../data"), PathPlatform::Posix);
    assert_eq!(normalize_resource(once.clone(), PathPlatform::Posix), once);

    let unc = normalize_resource(path(r"\\server\share\.\data"), PathPlatform::Windows);
    assert_eq!(unc, path("//server/share/data"));
    let selector = typed_selector(&unc);
    assert_eq!(
        identity_from_selector(selector.split_once(':').unwrap().1),
        Some(ResourceIdentity::FsPath {
            path: "//server/share/data".into()
        })
    );
}

#[test]
fn process_selector_round_trips_every_disambiguating_field() {
    let process = ResourceExpr::Concrete {
        identity: ResourceIdentity::Process {
            executable: "tool".into(),
            path: Some("/opt/./bin/tool".into()),
            argv: vec![
                ResourceExpr::Literal {
                    value: "--root".into(),
                },
                ResourceExpr::Parameter {
                    name: "root".into(),
                },
            ],
            cwd: Some(Box::new(path("/work/./tree"))),
        },
    };
    let canonical = normalize_resource(process, PathPlatform::Posix);
    let selector = typed_selector(&canonical);
    assert_eq!(
        identity_from_selector(selector.split_once(':').unwrap().1),
        match canonical {
            ResourceExpr::Concrete { identity } => Some(identity),
            _ => None,
        }
    );
}

#[test]
fn environment_and_git_identities_normalize_display_and_round_trip() {
    let environment = ResourceExpr::Concrete {
        identity: ResourceIdentity::EnvironmentVariable {
            name: "HOME".into(),
        },
    };
    assert_eq!(effinterp_proto::display_resource(&environment), "env:HOME");
    let selector = typed_selector(&environment);
    assert_eq!(
        identity_from_selector(selector.split_once(':').unwrap().1),
        Some(ResourceIdentity::EnvironmentVariable {
            name: "HOME".into()
        })
    );

    let git = normalize_resource(
        ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository {
                worktree: Some(Box::new(path("/repo/./work"))),
                git_dir: Some(Box::new(ResourceExpr::Parameter {
                    name: "git_dir".into(),
                })),
                pathspec: Some(Box::new(path("src/../tests"))),
            },
        },
        PathPlatform::Posix,
    );
    assert_eq!(
        effinterp_proto::display_resource(&git),
        "git:worktree=\"fs:/repo/work\";git_dir=\"<git_dir>\";pathspec=\"fs:tests\""
    );
    let ResourceExpr::Concrete { identity } = &git else {
        unreachable!()
    };
    let rendered = display_identity(identity);
    assert_eq!(
        GitIdentitySelector::parse(rendered.strip_prefix("git:").unwrap()),
        Some(GitIdentitySelector {
            worktree: Some("fs:/repo/work".into()),
            git_dir: Some("<git_dir>".into()),
            pathspec: Some("fs:tests".into()),
        })
    );
    let selector = typed_selector(&git);
    assert_eq!(
        identity_from_selector(selector.split_once(':').unwrap().1),
        Some(identity.clone())
    );
}

#[test]
fn network_and_database_displays_preserve_all_known_scope() {
    let network = ResourceIdentity::NetworkEndpoint {
        host: "2001:db8::1".into(),
        scheme: Some("https".into()),
        port: Some(8443),
        path: Some("api/v1".into()),
    };
    assert_eq!(
        display_identity(&network),
        "net:https://[2001:db8::1]:8443/api/v1"
    );

    let database = ResourceIdentity::DatabaseTable {
        server: Some("db;primary".into()),
        database: Some("app\"blue".into()),
        schema: Some("public".into()),
        table: "users".into(),
    };
    let rendered = display_identity(&database);
    assert_eq!(
        DatabaseIdentitySelector::parse(rendered.strip_prefix("db:").unwrap()),
        Some(DatabaseIdentitySelector {
            server: Some("db;primary".into()),
            database: Some("app\"blue".into()),
            schema: Some("public".into()),
            table: Some("users".into()),
        })
    );
}

#[test]
fn artifact_reference_scope_and_symbolic_fields_survive_canonical_selectors() {
    use effinterp_proto::{ArtifactEcosystem, ArtifactReference};
    let literal = |value: &str| ResourceExpr::Literal {
        value: value.into(),
    };
    let mut selectors = std::collections::BTreeSet::new();
    for ecosystem in [
        ArtifactEcosystem::Oci,
        ArtifactEcosystem::Npm,
        ArtifactEcosystem::GithubRelease,
    ] {
        for endpoint in [
            literal("registry.one"),
            literal("registry.two"),
            ResourceExpr::Environment {
                name: "REGISTRY".into(),
            },
        ] {
            for reference in [
                ArtifactReference::Version {
                    value: literal("v2"),
                },
                ArtifactReference::Tag {
                    value: literal("v2"),
                },
                ArtifactReference::Digest {
                    value: literal("v2"),
                },
                ArtifactReference::Whole {},
                ArtifactReference::Version {
                    value: ResourceExpr::Unresolved {
                        family: ResourceFamily::new("artifact"),
                    },
                },
            ] {
                let resource = ResourceExpr::Concrete {
                    identity: ResourceIdentity::Artifact {
                        ecosystem,
                        endpoint: Box::new(endpoint.clone()),
                        name: Box::new(literal("acme/api")),
                        reference: Box::new(reference),
                    },
                };
                let selector = typed_selector(&resource);
                assert_eq!(
                    identity_from_selector(selector.split_once(':').unwrap().1)
                        .map(|identity| ResourceExpr::Concrete { identity }),
                    Some(resource.clone())
                );
                assert_eq!(
                    normalize_resource(resource.clone(), PathPlatform::Posix),
                    resource
                );
                assert!(selector.starts_with("artifact:@"));
                assert!(selectors.insert(selector));
            }
        }
    }
    for ecosystem in [ArtifactEcosystem::Oci, ArtifactEcosystem::Npm] {
        let resource = |endpoint: &str| ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact {
                ecosystem,
                endpoint: Box::new(literal(endpoint)),
                name: Box::new(literal("acme/api")),
                reference: Box::new(ArtifactReference::Tag {
                    value: literal("v2"),
                }),
            },
        };
        assert_eq!(
            normalize_resource(resource("index.docker.io"), PathPlatform::Posix),
            resource(if ecosystem == ArtifactEcosystem::Oci {
                "docker.io"
            } else {
                "index.docker.io"
            }),
        );
    }
    let invalid = ResourceExpr::Concrete {
        identity: ResourceIdentity::Artifact {
            ecosystem: ArtifactEcosystem::Npm,
            endpoint: Box::new(literal("")),
            name: Box::new(literal("api")),
            reference: Box::new(ArtifactReference::Whole {}),
        },
    };
    let selector = typed_selector(&invalid);
    assert!(identity_from_selector(selector.split_once(':').unwrap().1).is_none());
}

fn path(value: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: value.into() },
    }
}
