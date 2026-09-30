use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{
    AttrValue, HostContext, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn analyze(command: &str, env: &[(&str, &str)]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: command.into(),
            cwd: Some("/work".into()),
            context: HostContext {
                env: env
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

#[test]
fn cargo_binary_selectors_resolve_only_under_the_selected_install_root() {
    for (command, env, operation, path) in [
        (
            "cargo uninstall --bin tool",
            vec![("HOME", "/home/test")],
            "filesystem.delete",
            "/home/test/.cargo/bin/tool",
        ),
        (
            "cargo +stable --quiet uninstall --root /tmp/tools --bin=tool",
            vec![("CARGO_HOME", "/elsewhere")],
            "filesystem.delete",
            "/tmp/tools/bin/tool",
        ),
        (
            "cargo uninstall --bin tool",
            vec![("HOME", "/home/test"), ("CARGO_HOME", "/cargo")],
            "filesystem.delete",
            "/cargo/bin/tool",
        ),
        (
            "CARGO_HOME=/other cargo uninstall --bin tool",
            vec![("CARGO_HOME", "/cargo")],
            "filesystem.delete",
            "/other/bin/tool",
        ),
        (
            "cargo uninstall --bin tool",
            vec![
                ("CARGO_HOME", "/cargo"),
                ("CARGO_INSTALL_ROOT", "/installed"),
            ],
            "filesystem.delete",
            "/installed/bin/tool",
        ),
        (
            "cargo install --path crates/package --bin tool --root ../tools",
            vec![],
            "filesystem.write",
            "/tools/bin/tool",
        ),
        (
            "cargo uninstall --bin first --bin second --root /tools",
            vec![],
            "filesystem.delete",
            "/tools/bin/second",
        ),
        // `--root` and `CARGO_INSTALL_ROOT` outrank an `install.root` a
        // `--config` may set.
        (
            "cargo uninstall --root /tools --config net.offline=true --bin tool",
            vec![],
            "filesystem.delete",
            "/tools/bin/tool",
        ),
        (
            "cargo --config net.offline=true uninstall --bin tool",
            vec![("CARGO_INSTALL_ROOT", "/installed")],
            "filesystem.delete",
            "/installed/bin/tool",
        ),
    ] {
        let plan = analyze(command, &env);
        assert!(plan.effects.iter().any(|effect| effect.operation.as_str() == operation
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == path)), "{command}: {plan:#?}");
    }
    let symbolic = analyze("cargo uninstall --bin tool", &[]);
    assert!(
        symbolic
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && matches!(effect.resource, ResourceExpr::Join { .. }))
    );
    assert!(
        !symbolic
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && matches!(effect.resource, ResourceExpr::Concrete { .. }))
    );
}

#[test]
fn cargo_package_and_path_selectors_do_not_invent_binary_names() {
    for (command, operation, root, key, selector) in [
        (
            "cargo uninstall nah-cli",
            "filesystem.delete",
            "/home/test/.cargo/bin",
            "package",
            "nah-cli",
        ),
        (
            "cargo uninstall --package nah-cli@1.0.0",
            "filesystem.delete",
            "/home/test/.cargo/bin",
            "package",
            "nah-cli@1.0.0",
        ),
        (
            "cargo +stable --quiet uninstall --root /tmp/tools nah-cli",
            "filesystem.delete",
            "/tmp/tools/bin",
            "package",
            "nah-cli",
        ),
        (
            "cargo install --path crates/nah-cli --locked --force --root /home/test/.local",
            "filesystem.write",
            "/home/test/.local/bin",
            "source_path",
            "crates/nah-cli",
        ),
        (
            "cargo install --path crates/nah-cli",
            "filesystem.write",
            "/home/test/.cargo/bin",
            "source_path",
            "crates/nah-cli",
        ),
        (
            "cargo uninstall --root nah other",
            "filesystem.delete",
            "/work/nah/bin",
            "package",
            "other",
        ),
        (
            "cargo uninstall -pother@2.0.0",
            "filesystem.delete",
            "/home/test/.cargo/bin",
            "package",
            "other@2.0.0",
        ),
    ] {
        let plan = analyze(command, &[("HOME", "/home/test")]);
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.as_str() == operation
                    && effect.attributes.contains_key("selection")
            })
            .collect();
        assert_eq!(effects.len(), 1, "{command}: {plan:#?}");
        assert_eq!(
            effects[0].resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: root.into() }
            },
            "{command}"
        );
        assert_eq!(
            effects[0].attributes.get(key),
            Some(&AttrValue::String(selector.into())),
            "{command}"
        );
        assert_eq!(
            effects[0].attributes.get("selection"),
            Some(&AttrValue::String(
                if key == "package" {
                    "package_binaries"
                } else {
                    "manifest_binaries"
                }
                .into()
            ))
        );
        assert!(
            plan.boundaries.iter().any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE),
            "{command}: {plan:#?}"
        );
        assert!(
            !plan.boundaries.iter().any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::UNRESOLVED_BUILD_TARGET),
            "{command}: {plan:#?}"
        );
        if operation == "filesystem.write" {
            assert_eq!(
                effects[0].attributes.get("disclosure"),
                Some(&AttrValue::String("contents".into()))
            );
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == "filesystem.read"
                        && effect.attributes.get("access_purpose")
                            == Some(&AttrValue::String("program_input".into())))
            );
        }
        assert!(!plan.effects.iter().any(|effect| effect.operation.as_str() == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                if path == "/home/test/.cargo/bin/nah" || path == "/home/test/.local/bin/nah")), "{command}");
    }
}

#[test]
fn cargo_non_mutating_modes_and_unresolved_selectors_do_not_claim_installation() {
    for command in [
        "cargo install",
        "cargo install --bin tool",
        "cargo uninstall nah-cli --help",
        "cargo install --list",
        "cargo install --path crates/package --root /tools --dry-run",
        "cargo install --path crates/package -n",
        "cargo uninstall --root",
        "cargo uninstall --bin",
        "cargo uninstall --bin tool --root /one --root /two",
        "cargo uninstall --bin tool --unknown /elsewhere",
        "cargo uninstall --bin tool --config install.root=\"/elsewhere\"",
        "cargo uninstall --bin ../tool",
        "cargo uninstall --bin 'tool*'",
        "cargo uninstall --bin \"$UNKNOWN\"",
        "cargo install --path crates/package --force=false",
    ] {
        let plan = analyze(command, &[("HOME", "/home/test")]);
        assert!(
            !plan.effects.iter().any(|effect| matches!(
                effect.operation.as_str(),
                "filesystem.write" | "filesystem.delete"
            )),
            "{command}: {plan:#?}"
        );
        if !command.contains("--help") && !command.contains("--list") {
            assert!(!plan.boundaries.is_empty(), "{command}");
        }
    }
    // An informational global mode prints and exits before any subcommand, so
    // it neither installs, removes nor asks the registry for a package.
    for command in [
        "cargo --help uninstall nah-cli",
        "cargo -h install tool",
        "cargo --version install nah-cli",
        "cargo -V uninstall --bin tool",
        "cargo --quiet --list install tool",
        "cargo --explain E0001 uninstall tool",
    ] {
        let plan = analyze(command, &[("HOME", "/home/test")]);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.attributes.contains_key("package_manager")),
            "{command}: {plan:#?}"
        );
    }
    for command in [
        "cargo fmt --all --check",
        "cargo +stable --quiet fmt --check",
    ] {
        let plan = analyze(command, &[]);
        assert!(paths(&plan, "filesystem.write").is_empty(), "{command}");
        assert!(plan.boundaries.is_empty(), "{plan:#?}");
    }
    let format = analyze("cargo fmt --all", &[]);
    assert_eq!(paths(&format, "filesystem.write").len(), 1);
    let package = analyze("cargo package", &[]);
    assert!(
        package
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::UNMODELED_HOOKS)
    );
    assert_eq!(paths(&package, "filesystem.write").len(), 1);
    for command in [
        "cargo yank --version 1.0.0 crate-name",
        "cargo yank crate-name@1.0.0",
    ] {
        let plan = analyze(command, &[]);
        assert!(plan.boundaries.is_empty(), "{plan:#?}");
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "artifact.yank_request")
            .unwrap();
        assert_eq!(
            request.attributes.get("package"),
            Some(&AttrValue::String("crate-name".into()))
        );
        assert_eq!(
            request.attributes.get("version"),
            Some(&AttrValue::String("1.0.0".into()))
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| !effect.operation.as_str().contains("delete"))
        );
    }
}

/// Cargo's own install registry, when the host supplies it.
const CRATES2: &str = r#"{"installs":{
  "nah-cli 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)":
    {"version_req":null,"bins":["nah","nah-doctor"],"features":[],"all_features":false,
     "no_default_features":false,"profile":"release","target":"x86_64-unknown-linux-gnu","rustc":"rustc 1.0.0"},
  "other 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)":
    {"version_req":null,"bins":["othertool"],"features":[],"all_features":false,
     "no_default_features":false,"profile":"release","target":"x86_64-unknown-linux-gnu","rustc":"rustc 1.0.0"}
}}"#;

struct InstallRegistry(&'static str);

impl SourceResolver for InstallRegistry {
    fn source_mutation_disjoint(&self, _: &ResourceExpr, _: SourceRequest<'_>) -> bool {
        true
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }

    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        if request.path == self.0 {
            SourceResponse::Source(CRATES2.as_bytes().to_vec())
        } else {
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
        }
    }
}

fn analyze_with_registry(command: &str, registry: &'static str) -> Plan {
    let plan = Engine::new()
        .with_resolver(Box::new(InstallRegistry(registry)))
        .analyze(&Subject::Shell {
            source: command.into(),
            cwd: Some("/work".into()),
            context: HostContext {
                env: [("HOME".to_string(), "/home/test".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn paths(plan: &Plan, operation: &str) -> Vec<String> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.as_str() == operation)
        .map(|effect| effinterp_proto::display_resource(&effect.resource))
        .collect()
}

fn details(plan: &Plan) -> Vec<&str> {
    plan.boundaries
        .iter()
        .filter_map(|boundary| boundary.detail.as_deref())
        .collect()
}

#[test]
fn cargo_resolves_package_binaries_only_from_the_supplied_install_registry() {
    const REGISTRY: &str = "/home/test/.cargo/.crates2.json";

    // A recorded package selects exactly the binaries Cargo recorded for it.
    let removed = analyze_with_registry("cargo uninstall nah-cli", REGISTRY);
    assert_eq!(
        paths(&removed, "filesystem.delete"),
        [
            "fs:/home/test/.cargo/bin/nah",
            "fs:/home/test/.cargo/bin/nah-doctor"
        ],
        "{removed:#?}"
    );
    let other = analyze_with_registry("cargo uninstall other", REGISTRY);
    assert_eq!(
        paths(&other, "filesystem.delete"),
        ["fs:/home/test/.cargo/bin/othertool"],
        "{other:#?}"
    );
    let versioned = analyze_with_registry("cargo uninstall --package nah-cli@1.0.0", REGISTRY);
    assert_eq!(
        paths(&versioned, "filesystem.delete"),
        [
            "fs:/home/test/.cargo/bin/nah",
            "fs:/home/test/.cargo/bin/nah-doctor"
        ],
    );
    // Cargo refuses to uninstall a package the registry does not record.
    let absent = analyze_with_registry("cargo uninstall unrecorded", REGISTRY);
    assert_eq!(
        paths(&absent, "filesystem.delete"),
        [] as [String; 0],
        "{absent:#?}"
    );

    assert!(removed.boundaries.is_empty(), "{removed:#?}");
    assert!(absent.boundaries.is_empty(), "{absent:#?}");
    assert!(paths(&absent, "filesystem.write").is_empty());
    let wrong_version = analyze_with_registry("cargo uninstall --package nah-cli@2.0.0", REGISTRY);
    assert!(paths(&wrong_version, "filesystem.delete").is_empty());

    // A new build may change its binaries; old installation metadata is not a manifest.
    let reinstall = analyze_with_registry("cargo install nah-cli", REGISTRY);
    for plan in [
        reinstall,
        analyze_with_registry("cargo install unrecorded", REGISTRY),
    ] {
        assert_eq!(
            paths(&plan, "filesystem.write"),
            [
                "fs:/home/test/.cargo/bin",
                "fs:/home/test/.cargo/.crates.toml",
                "fs:/home/test/.cargo/.crates2.json",
            ]
        );
        assert!(
            plan.boundaries.iter().any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::OBSERVATION_UNAVAILABLE)
        );
    }

    // Without the registry the package remainder names the file that closes it.
    let unobserved = analyze_with_registry("cargo uninstall nah-cli", "/elsewhere");
    assert_eq!(
        paths(&unobserved, "filesystem.delete"),
        ["fs:/home/test/.cargo/bin"]
    );
    assert!(
        details(&unobserved)
            .iter()
            .any(|detail| detail.contains("/home/test/.cargo/.crates2.json is not observed")),
        "{:?}",
        details(&unobserved)
    );
}

#[test]
fn cargo_install_bins_flag() {
    let plan = analyze(
        "cargo install --root /home/test/.local --path crates/tool --bins",
        &[],
    );
    let writes = paths(&plan, "filesystem.write");
    assert!(
        writes.contains(&"fs:/home/test/.local/bin".to_string()),
        "{writes:?}"
    );
    assert!(
        !details(&plan)
            .iter()
            .any(|detail| detail.contains("not statically supported"))
    );
}
