use effinterp_engine::{
    Engine, SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
};
use effinterp_proto::{
    ArtifactEcosystem, ArtifactReference, Plan, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};

struct Manifest(&'static str);
impl SourceResolver for Manifest {
    fn source_mutation_disjoint(
        &self,
        _: &effinterp_proto::ResourceExpr,
        _: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        true
    }

    fn siblings(&self, _: &str) -> Option<Vec<String>> {
        None
    }
    fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
        if request.path.ends_with("package.json") {
            SourceResponse::Source(self.0.as_bytes().to_vec())
        } else {
            SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
        }
    }
}
const PACKAGE: &str = r#"{"name":"@acme/api","version":"1.2.3","publishConfig":{"registry":"https://registry.example","@acme:registry":"https://registry.example"},"scripts":{"prepack":"touch hook-output","prepare":"touch prepared.txt"}}"#;
fn analyze(source: &str, manifest: Option<&'static str>) -> Plan {
    let engine = if let Some(manifest) = manifest {
        Engine::new().with_resolver(Box::new(Manifest(manifest)))
    } else {
        Engine::new()
    };
    let plan = engine
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap_or_else(|error| panic!("{source}: {error:?}"));
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid {source}: {e:?}"));
    plan
}
fn artifacts(plan: &Plan) -> Vec<(&str, &ResourceIdentity)> {
    plan.effects
        .iter()
        .filter_map(|e| match &e.resource {
            ResourceExpr::Concrete {
                identity: identity @ ResourceIdentity::Artifact { .. },
            } => Some((e.operation.as_str(), identity)),
            _ => None,
        })
        .collect()
}
fn lit(value: &str) -> ResourceExpr {
    ResourceExpr::Literal {
        value: value.into(),
    }
}

#[test]
fn literal_package_publication_has_typed_request_and_rejects_unknown_controls() {
    let archive = analyze("npm publish package.tgz", Some(PACKAGE));
    assert!(archive.effects.iter().any(|effect| {
        effect.operation.as_str() == "artifact.publish"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::Artifact { name, .. }
            } if matches!(name.as_ref(), ResourceExpr::Unresolved { .. }))
    }));
    assert!(!archive.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path.ends_with("package.json"))
    }));
    let tarball = archive
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "filesystem.read")
        .expect("npm should read the selected tarball");
    assert_eq!(
        tarball.attributes.get("access_purpose"),
        Some(&effinterp_proto::AttrValue::String("program_input".into()))
    );
    assert_eq!(
        tarball.attributes.get("disclosure"),
        Some(&effinterp_proto::AttrValue::String("contents".into()))
    );
    assert!(archive.effects.iter().any(|effect| {
        effect.operation.as_str() == "network.upload"
            && effect.attributes.get("disclosure")
                == Some(&effinterp_proto::AttrValue::String("contents".into()))
    }));
    assert!(
        !archive
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::PACKAGE_SCRIPTS)
    );
    let plan = analyze("gem push pkg.gem", None);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.class == effinterp_proto::BoundaryClass::Unmodeled
            && boundary.reason == effinterp_proto::BoundaryReason::ENVIRONMENT_CONFIGURATION
    }));
    assert!(
        archive
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == effinterp_proto::BoundaryReason::MODEL_COVERAGE })
    );
    let build = analyze("poetry publish --build --repository pypi", None);
    assert!(build.boundaries.iter().any(|boundary| {
        boundary.class == effinterp_proto::BoundaryClass::Unmodeled
            && boundary.reason == effinterp_proto::BoundaryReason::PACKAGE_SCRIPTS
    }));
    assert!(
        build
            .boundaries
            .iter()
            .any(|boundary| { boundary.domains.iter().any(|domain| domain.0 == "process") })
    );
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "artifact.publish_request")
        .expect("gem push should produce a publication request");
    assert!(matches!(request.resource, ResourceExpr::Unresolved { .. }));
    assert_eq!(request.modality, effinterp_proto::Modality::MustOnSuccess);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "artifact.publish"
            && effect.modality == effinterp_proto::Modality::May
    }));
    assert_eq!(
        request.attributes.get("active"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("dry_run"),
        Some(&effinterp_proto::AttrValue::Bool(false))
    );
    for command in [
        "npm publish package.tgz --tag next --access public --registry http://localhost:4873 --otp 123456",
        "npm publish --no-dry-run",
        "pnpm publish package.tgz --tag latest",
        "yarn npm publish --access public --tag next",
        "bun publish package.tgz --access public",
        "/usr/bin/npm publish --no-dry-run",
        "/usr/bin/bun publish package.tgz --access public",
        "/usr/bin/uv publish --index pypi --check-url https://pypi.org/simple",
        "gem push pkg.gem --host https://rubygems.org --otp 123456",
        "python -m twine upload dist/pkg.whl",
        "poetry publish --build --repository pypi",
        "hatch publish dist/* --repo main",
        "flit publish --repository pypi",
        "pnpm dlx npm publish --tag next",
        "twine upload -r testpypi --skip-existing --non-interactive dist/*",
        "twine upload --attestations --sign --identity me@example.com --cert ca.pem dist/pkg.whl",
        "uv publish --index pypi --check-url https://pypi.org/simple",
        "uv publish --trusted-publishing always --no-attestations --offline dist/pkg.whl",
        "hatch publish -r main -n --initialize-auth -o foo=bar dist/pkg.whl",
        "hatch publish --publisher index --yes",
        // An option npm's reading does not understand keeps the request.
        "npm publish --access",
    ] {
        let plan = analyze(command, None);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "artifact.publish"),
            "{command}"
        );
    }
    for command in [
        "pnpm publish package.tgz --tag",
        "yarn npm publish --unknown",
        "yarn npm publish --registry https://registry.example",
        "yarn npm publish package.tgz",
        "bun publish package.tgz --access",
        "gem push pkg.gem --otp",
        "python -m twine check dist/pkg.whl",
        "poetry publish --repository",
        "hatch publish --repo",
        "flit publish --repository",
        "pnpm dlx --package npm publish",
        "npm publish package.tgz --dry-run",
        "pnpm publish package.tgz --dry-run",
        "yarn npm publish --dry-run",
        "bun publish package.tgz --dry-run",
        "hatch publish --dry-run",
        "twine upload --dry-run dist/pkg.whl",
        // Only a bare or system-directory path establishes the tool.
        "/usr/local/bin/npm publish --no-dry-run",
        "./bun publish package.tgz --access public",
        "/home/user/bin/uv publish --index pypi --check-url https://pypi.org/simple",
    ] {
        let plan = analyze(command, None);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "artifact.publish"),
            "{command}"
        );
    }
    let invalid = analyze("gem push --unknown pkg.gem", None);
    assert!(
        !invalid
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.publish")
    );
    assert!(
        invalid
            .boundaries
            .iter()
            .any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS)
    );
    // `--help` aborts the publication, but it does not make a malformed
    // option list understood: the clients reject the invocation instead.
    let help_after_missing_value = analyze("cargo publish --registry --help", None);
    assert!(
        help_after_missing_value
            .boundaries
            .iter()
            .any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS)
    );
    assert!(
        analyze("twine upload --help", None)
            .boundaries
            .iter()
            .all(|boundary| boundary.reason
                != effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS)
    );
    let dry = analyze("uv publish --dry-run dist/pkg.whl", None);
    assert!(
        !dry.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.publish")
    );
    for command in [
        "cargo publish junk",
        "poetry publish junk",
        "flit publish junk",
        "gem yank example",
        "gem push -v pkg.gem",
    ] {
        let plan = analyze(command, None);
        assert!(
            !plan.effects.iter().any(|effect| {
                matches!(
                    effect.operation.as_str(),
                    "artifact.publish_request" | "artifact.yank_request"
                )
            }),
            "{command} must not be an exact package request"
        );
    }
    let yank = analyze("gem yank example -v 1.2.3", None);
    let yank = yank
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "artifact.yank_request")
        .expect("gem yank with a version should be typed");
    assert_eq!(
        yank.attributes.get("package"),
        Some(&effinterp_proto::AttrValue::String("example".into()))
    );
    assert_eq!(
        yank.attributes.get("scope"),
        Some(&effinterp_proto::AttrValue::String("version".into()))
    );
    assert_eq!(
        yank.attributes.get("version"),
        Some(&effinterp_proto::AttrValue::String("1.2.3".into()))
    );
    let yank_equals = analyze(
        "gem yank example -v 1.0.0 --version=1.2.4 --platform ruby --otp 123456 --host https://rubygems.org",
        None,
    );
    assert!(
        yank_equals
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.delete")
    );
    assert!(
        yank_equals
            .effects
            .iter()
            .any(
                |effect| effect.operation.as_str() == "artifact.yank_request"
                    && effect.attributes.get("version")
                        == Some(&effinterp_proto::AttrValue::String("1.2.4".into()))
            )
    );
    for effect in yank_equals
        .effects
        .iter()
        .filter(|effect| effect.operation.domain() == "artifact")
    {
        assert_eq!(
            effect.attributes.get("registry"),
            Some(&effinterp_proto::AttrValue::String(
                "https://rubygems.org".into()
            ))
        );
        assert_eq!(
            effect.attributes.get("platform"),
            Some(&effinterp_proto::AttrValue::String("ruby".into()))
        );
    }
    for (command, key, value) in [
        (
            "twine upload -r first --repository last dist/pkg.whl",
            "registry_name",
            "last",
        ),
        (
            "twine upload --repository first -r last dist/pkg.whl",
            "registry_name",
            "last",
        ),
        (
            "nuget push renamed.nupkg -Source private-feed",
            "registry_name",
            "private-feed",
        ),
        (
            "cargo publish --registry private",
            "registry_name",
            "private",
        ),
        (
            "gem push renamed.gem --host https://gems.example",
            "registry",
            "https://gems.example",
        ),
        (
            "dotnet nuget push renamed.nupkg --source https://nuget.example/index.json",
            "registry",
            "https://nuget.example/index.json",
        ),
    ] {
        let plan = analyze(command, None);
        let request = plan
            .effects
            .iter()
            .find(|e| e.operation.as_str() == "artifact.publish_request")
            .unwrap();
        assert_eq!(
            request.attributes.get(key),
            Some(&effinterp_proto::AttrValue::String(value.into()))
        );
        assert!(!request.attributes.contains_key("package"));
        assert!(!request.attributes.contains_key("version"));
    }
    assert!(
        analyze("uv publish", None)
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.publish_request")
    );
    // A package.json that supplies the identity must not weaken the request.
    for (command, operation, manifest) in [
        (
            "npm publish --ignore-scripts",
            "artifact.publish_request",
            None,
        ),
        (
            "npm unpublish @acme/api@1.2.3 --ignore-scripts",
            "artifact.remove_request",
            None,
        ),
        ("gem push pkg.gem", "artifact.publish_request", None),
        ("npm publish", "artifact.publish_request", Some(PACKAGE)),
        (
            "npm unpublish @acme/api@1.2.3",
            "artifact.remove_request",
            Some(PACKAGE),
        ),
        ("pnpm publish", "artifact.publish_request", Some(PACKAGE)),
    ] {
        let plan = analyze(command, manifest);
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == operation)
            .unwrap_or_else(|| panic!("{command} must retain its request"));
        assert_eq!(
            request.request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{command}"
        );
    }
    let yank = analyze("gem yank pkg* -v 1.2.3", None);
    let yank = yank
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "artifact.yank_request")
        .expect("pattern yank keeps the requested action");
    assert_eq!(
        yank.request_assurance,
        effinterp_proto::RequestAssurance::Conservative
    );
    let pattern = analyze("twine upload dist/*.whl", None);
    let pattern_request = pattern
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "artifact.publish_request")
        .expect("pattern publication keeps the requested action");
    assert_eq!(
        pattern_request.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        pattern_request.attributes.get("selection"),
        Some(&effinterp_proto::AttrValue::String("pattern".into()))
    );
}
fn assert_target(
    plan: &Plan,
    op: &str,
    ecosystem: ArtifactEcosystem,
    endpoint: &str,
    name: &str,
    reference: ArtifactReference,
) {
    assert!(
        artifacts(plan)
            .iter()
            .any(|(operation, identity)| *operation == op
                && **identity
                    == ResourceIdentity::Artifact {
                        ecosystem,
                        endpoint: Box::new(lit(endpoint)),
                        name: Box::new(lit(name)),
                        reference: Box::new(reference.clone())
                    }),
        "missing target: {:?}",
        artifacts(plan)
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.as_str() == "process.exec")
    );
    assert!(
        plan.effects.iter().any(|effect| {
            if ecosystem == ArtifactEcosystem::GithubRelease && op == "artifact.delete" {
                effect.operation.as_str() == "network.delete_request"
                    && effect.attributes.get("method")
                        == Some(&effinterp_proto::AttrValue::String("DELETE".into()))
            } else {
                effect.operation.as_str() == "network.upload"
            }
        }),
        "missing transport evidence for {op} {ecosystem:?} {endpoint} {name}"
    );
}

// New typed targets are not exercised by older command coverage. These rows
// catch lost remote mutations and false publication on local/dry/draft paths.
#[test]
fn artifact_command_behavior_matrix() {
    for (command, endpoint) in [
        ("docker push ghcr.io/acme/api:v2", "ghcr.io"),
        ("docker push acme/api:v2", "docker.io"),
        ("docker push index.docker.io/acme/api:v2", "docker.io"),
        ("docker push docker.io/acme/api:v2", "docker.io"),
        (
            "docker image push -q registry.example:5000/acme/api:v2",
            "registry.example:5000",
        ),
    ] {
        assert_target(
            &analyze(command, None),
            "artifact.publish",
            ArtifactEcosystem::Oci,
            endpoint,
            "acme/api",
            ArtifactReference::Tag { value: lit("v2") },
        );
    }
    assert_target(
        &analyze("docker push index.docker.io/alpine:V2", None),
        "artifact.publish",
        ArtifactEcosystem::Oci,
        "docker.io",
        "library/alpine",
        ArtifactReference::Tag { value: lit("V2") },
    );
    for command in ["docker push ghcr.io/acme/API:v2", "docker push acme/API:v2"] {
        let plan = analyze(command, Some(PACKAGE));
        assert!(artifacts(&plan).is_empty(), "false publication: {command}");
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| { boundary.domains.iter().any(|domain| domain.0 == "artifact") }),
            "missing artifact boundary: {command}"
        );
    }
    // A prefix moves an unpublish's package directory, an undefined option
    // may take `sub` as its value, and a missing or unproven value may
    // relocate or suppress it: the request stays, its package unresolved.
    for command in [
        "npm --prefix sub unpublish",
        "npm --unknown sub publish",
        "npm publish --registry",
        "npm publish --dry-run=maybe",
    ] {
        let plan = analyze(command, Some(PACKAGE));
        assert!(
            plan.effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::Artifact { name, .. } }
                    if matches!(name.as_ref(), ResourceExpr::Unresolved { .. })
            )),
            "{command}"
        );
    }
    let all = analyze("docker push --all-tags ghcr.io/acme/api", None);
    assert!(
        matches!(artifacts(&all)[0].1, ResourceIdentity::Artifact { name, reference, .. } if **name == lit("acme/api") && matches!(reference.as_ref(), ArtifactReference::Tag { value: ResourceExpr::Pattern { .. } }))
    );
    let pattern = artifacts(&all)[0].1.clone();
    let mut concrete = pattern.clone();
    let ResourceIdentity::Artifact { reference, .. } = &mut concrete else {
        unreachable!()
    };
    *reference = Box::new(ArtifactReference::Tag { value: lit("v2") });
    assert!(matches!(
        effinterp_proto::satisfies(
            &effinterp_proto::QualifiedIdentity {
                realm: Default::default(),
                identity: concrete
            },
            &effinterp_proto::QualifiedExpr {
                realm: Default::default(),
                expr: ResourceExpr::Concrete { identity: pattern }
            },
            &effinterp_proto::Bindings::none(effinterp_proto::PathPlatform::Posix),
        ),
        effinterp_proto::Match::Satisfied { .. }
    ));
    assert!(!all.boundaries.is_empty());
    // NuGet's delete unlists the version: the published identity survives and
    // the owner can relist it, so this is the same shape as a gem yank.
    let nuget_delete = analyze("dotnet nuget delete package 1.0.0", None);
    let request = nuget_delete
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "artifact.yank_request")
        .expect("dotnet nuget delete should produce an exact unlist request");
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        request.attributes.get("package"),
        Some(&effinterp_proto::AttrValue::String("package".into()))
    );
    assert_eq!(
        request.attributes.get("version"),
        Some(&effinterp_proto::AttrValue::String("1.0.0".into()))
    );
    assert!(
        nuget_delete
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.delete")
    );
    assert_target(
        &analyze("docker push alpine", None),
        "artifact.publish",
        ArtifactEcosystem::Oci,
        "docker.io",
        "library/alpine",
        ArtifactReference::Tag {
            value: lit("latest"),
        },
    );
    let symbolic = analyze("docker push ghcr.io/acme/api:$TAG", None);
    assert!(
        matches!(artifacts(&symbolic)[0].1, ResourceIdentity::Artifact { endpoint, name, reference, .. } if **endpoint == lit("ghcr.io") && **name == lit("acme/api") && !matches!(reference.value(), Some(ResourceExpr::Literal { .. })))
    );
    for command in [
        "docker push $ORG/api",
        "docker push $ORG/api:v2",
        "docker push $REGISTRY/acme/api:v2",
    ] {
        let symbolic = analyze(command, None);
        assert!(
            matches!(artifacts(&symbolic)[0].1, ResourceIdentity::Artifact { endpoint, name, reference, .. }
            if matches!(endpoint.as_ref(), ResourceExpr::Unresolved { .. })
                && matches!(name.as_ref(), ResourceExpr::Unresolved { .. })
                && if command.ends_with(":v2") {
                    reference.value() == Some(&lit("v2"))
                } else {
                    matches!(reference.value(), Some(ResourceExpr::Unresolved { .. }))
                })
        );
        assert!(
            symbolic
                .boundaries
                .iter()
                .any(|boundary| { boundary.domains.iter().any(|domain| domain.0 == "artifact") })
        );
    }
    // npm 11 publishes the current directory whatever the prefix names.
    for command in [
        "npm publish --tag beta --ignore-scripts",
        "npm --tag=beta publish . --ignore-scripts=true",
        "npm --prefix sub publish --tag beta --ignore-scripts",
    ] {
        let plan = analyze(command, Some(PACKAGE));
        for operation in ["artifact.publish", "artifact.publish_request"] {
            let effect = plan
                .effects
                .iter()
                .find(|effect| effect.operation.as_str() == operation)
                .unwrap();
            assert_eq!(
                effect.attributes.get("action"),
                Some(&effinterp_proto::AttrValue::String("publish".into()))
            );
            assert_eq!(
                effect.attributes.get("selection"),
                Some(&effinterp_proto::AttrValue::String("unknown".into()))
            );
        }
        assert_target(
            &plan,
            "artifact.publish",
            ArtifactEcosystem::Npm,
            "https://registry.example",
            "@acme/api",
            ArtifactReference::Version {
                value: lit("1.2.3"),
            },
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.as_str() == "artifact.publish"
                    && e.attributes.get("tag")
                        == Some(&effinterp_proto::AttrValue::String("beta".into())))
        );
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.as_str() == "filesystem.read")
        );
    }
    for (command, reference) in [
        (
            "npm unpublish @acme/api@1.2.3 --registry https://registry.example",
            ArtifactReference::Version {
                value: lit("1.2.3"),
            },
        ),
        (
            "npm unpublish @acme/api --force",
            ArtifactReference::Whole {},
        ),
    ] {
        let plan = analyze(command, None);
        assert!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.as_str().starts_with("artifact.delete"))
                .all(|effect| !effect.attributes.contains_key("action")
                    && !effect.attributes.contains_key("selection"))
        );
        assert!(plan.boundaries.iter().all(|boundary| boundary.reason
            == effinterp_proto::BoundaryReason::ENVIRONMENT_CONFIGURATION));
        let physical = artifacts(&plan)
            .into_iter()
            .find(|(operation, _)| *operation == "artifact.delete")
            .expect("physical removal effect");
        assert!(
            matches!(physical.1, ResourceIdentity::Artifact { name, reference: got, .. } if **name == lit("@acme/api") && **got == reference)
        );
    }
    assert_target(
        &analyze("npm unpublish", Some(PACKAGE)),
        "artifact.delete",
        ArtifactEcosystem::Npm,
        "https://registry.example",
        "@acme/api",
        ArtifactReference::Version {
            value: lit("1.2.3"),
        },
    );
    for (command, registry) in [
        (
            "npm unpublish api@1.2.3 --registry https://cli.example",
            "https://cli.example",
        ),
        ("npm unpublish api@1.2.3", "https://manifest.example"),
        (
            "npm publish --registry https://cli.example --ignore-scripts",
            "https://cli.example",
        ),
    ] {
        assert_target(
            &analyze(
                command,
                Some(
                    r#"{"name":"api","version":"1.2.3","publishConfig":{"registry":"https://manifest.example"}}"#,
                ),
            ),
            if command.contains("unpublish") {
                "artifact.delete"
            } else {
                "artifact.publish"
            },
            ArtifactEcosystem::Npm,
            registry,
            "api",
            ArtifactReference::Version {
                value: lit("1.2.3"),
            },
        );
    }
    for command in ["pnpm publish", "bun publish", "yarn npm publish"] {
        let plan = analyze(command, Some(PACKAGE));
        assert!(
            matches!(artifacts(&plan)[0].1, ResourceIdentity::Artifact { name, reference, .. }
            if **name == lit("@acme/api") && reference.value() == Some(&lit("1.2.3")))
        );
    }
    for command in [
        "pnpm publish package.tgz",
        "bun publish package.tgz",
        "yarn publish package.tgz",
    ] {
        let archive = analyze(command, Some(PACKAGE));
        assert!(
            matches!(artifacts(&archive)[0].1, ResourceIdentity::Artifact { name, reference, .. }
            if matches!(name.as_ref(), ResourceExpr::Unresolved { .. }) && matches!(reference.value(), Some(ResourceExpr::Unresolved { .. })))
        );
    }
    let classic = analyze("yarn publish", Some(PACKAGE));
    assert!(
        matches!(artifacts(&classic)[0].1, ResourceIdentity::Artifact { name, reference, .. }
        if **name == lit("@acme/api") && matches!(reference.value(), Some(ResourceExpr::Unresolved { .. })))
    );
    let redirected = analyze(
        "pnpm publish",
        Some(r#"{"name":"api","version":"1.2.3","publishConfig":{"directory":"dist"}}"#),
    );
    assert!(
        matches!(artifacts(&redirected)[0].1, ResourceIdentity::Artifact { name, .. }
        if matches!(name.as_ref(), ResourceExpr::Unresolved { .. }))
    );
    let scoped = analyze(
        "npm publish --registry https://registry.example --ignore-scripts",
        Some(
            r#"{"name":"@acme/api","version":"1.2.3","publishConfig":{"registry":"https://registry.example"}}"#,
        ),
    );
    assert!(
        matches!(artifacts(&scoped)[0].1, ResourceIdentity::Artifact { endpoint, .. } if matches!(endpoint.as_ref(), ResourceExpr::Unresolved { .. }))
    );
    for (command, publication, hooks, directory) in [
        ("npm publish", true, true, "/w"),
        (
            "npm publish --dry-run=true --ignore-scripts false",
            false,
            true,
            "/w",
        ),
        ("npm publish pkg", true, true, "/w/pkg"),
        ("npm publish ./pkg", true, true, "/w/pkg"),
        ("npm publish /w/pkg", true, true, "/w/pkg"),
        ("npm publish pkg --dry-run", false, true, "/w/pkg"),
        ("npm publish pkg --ignore-scripts", true, false, "/w/pkg"),
        (
            "npm publish pkg --dry-run --ignore-scripts",
            false,
            false,
            "/w/pkg",
        ),
    ] {
        let plan = analyze(command, Some(PACKAGE));
        assert_eq!(!artifacts(&plan).is_empty(), publication, "{command}");
        if !publication {
            assert!(
                plan.effects
                    .iter()
                    .any(|e| e.operation.as_str() == "network.request")
            );
        }
        for output in ["hook-output", "prepared.txt"] {
            assert_eq!(
                plan.effects
                    .iter()
                    .any(|e| e.operation.as_str() == "process.exec"
                        && matches!(&e.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { executable, argv, .. }
                    } if executable == "touch" && *argv == vec![lit(output)])),
                hooks,
                "{command}: process for {output}"
            );
            assert_eq!(
                plan.effects
                    .iter()
                    .any(|e| e.operation.as_str() == "filesystem.metadata"
                        && matches!(&e.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if *path == format!("{directory}/{output}"))),
                hooks,
                "{command}: filesystem effect for {output}"
            );
            assert!(
                !plan.effects.iter().any(|e| e.operation.as_str() == "filesystem.metadata"
                    && matches!(&e.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path.ends_with(&format!("/{output}")) && *path != format!("{directory}/{output}"))),
                "{command}: filesystem effect in the wrong directory for {output}"
            );
        }
    }
    for command in ["npm publish --dry-run", "npm unpublish --dry-run=true"] {
        assert!(artifacts(&analyze(command, Some(PACKAGE))).is_empty());
    }
    assert!(
        artifacts(&analyze(
            "npm publish",
            Some(r#"{"name":"private","version":"1.0.0","private":true}"#)
        ))
        .is_empty()
    );
    for manifest in [None, Some("{"), Some(r#"{"name":"api","version":"1.0.0"}"#)] {
        let plan = analyze("npm publish", manifest);
        assert!(
            matches!(artifacts(&plan)[0].1, ResourceIdentity::Artifact { endpoint, .. } if matches!(endpoint.as_ref(), ResourceExpr::Unresolved { .. }))
        );
    }
    for (command, op) in [
        (
            "gh release create v2 --repo github.example/acme/api",
            "artifact.publish",
        ),
        (
            "gh release new --draft=true v2 -R github.example/acme/api",
            "artifact.create",
        ),
        (
            "gh release delete v2 --yes --repo=github.example/acme/api",
            "artifact.delete",
        ),
    ] {
        let plan = analyze(command, None);
        assert_target(
            &plan,
            op,
            ArtifactEcosystem::GithubRelease,
            "github.example",
            "acme/api",
            ArtifactReference::Tag { value: lit("v2") },
        );
        assert_eq!(artifacts(&plan).len(), 1);
    }
    let draft_asset = analyze("gh release create v2 --draft false -R acme/api", None);
    assert_eq!(artifacts(&draft_asset)[0].0, "artifact.create");
    assert!(
        !draft_asset
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "artifact.publish")
    );
    let release = analyze(
        "gh release create v2 asset.zip --notes-file notes.md --verify-tag -R acme/api",
        None,
    );
    assert_eq!(
        release
            .effects
            .iter()
            .filter(|e| e.operation.as_str() == "filesystem.read" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path.ends_with("asset.zip") || path.ends_with("notes.md")))
            .count(),
        2
    );
    assert!(
        !release
            .boundaries
            .iter()
            .any(|b| b.domains.iter().any(|d| d.0 == "git"))
    );
    let delete = analyze("gh release delete v2 -R acme/api --cleanup-tag", None);
    assert!(
        delete
            .boundaries
            .iter()
            .any(|b| b.domains.iter().any(|d| d.0 == "git"))
    );
    assert!(!delete.effects.iter().any(|e| e.operation.domain() == "git"));
    let stdin = analyze(
        "printf notes | gh release create v2 --notes-file - -R acme/api",
        None,
    );
    assert!(
        stdin
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "artifact.publish")
    );
    for command in [
        "docker push ghcr.io/acme/api:*",
        "docker push $IMAGE",
        "npm publish --registry=$REGISTRY",
        "gh release create $TAG -R acme/api",
    ] {
        let symbolic = analyze(command, Some(PACKAGE));
        assert!(!symbolic.boundaries.is_empty());
    }
    let missing = analyze("gh release create", None);
    assert!(
        matches!(artifacts(&missing)[0].1, ResourceIdentity::Artifact { endpoint, reference, .. } if matches!(endpoint.as_ref(), ResourceExpr::Unresolved { .. }) && matches!(reference.value(), Some(ResourceExpr::Unresolved { .. })))
    );
    for command in [
        "docker rmi api",
        "docker image rm api",
        "podman push api",
        "npm pack",
        "npm install --ignore-scripts",
        "gh release list",
        "gh release view v2",
        "docker pushy api",
        "npm publisher",
        "yarn unpublish",
        "gh release creates v2",
        "docker push api --platform linux/amd64",
        "docker push api --unknown",
        "docker push ghcr.io/acme/api@sha256:deadbeef",
        "docker push",
        "npm unpublish api@beta",
        "npm unpublish api@^1.2.3",
        "docker push ghcr.io/acme/api:v2 --all-tags",
        "docker --context prod push ghcr.io/acme/api:v2",
        "npm publish https://example/pkg.tgz",
        "gh release create v2 --repo",
        "gh release create v2 --draft=maybe",
        "gh release create v2 --unknown",
        "gh release create v2 --notes hi --notes-file x",
    ] {
        let plan = analyze(command, Some(PACKAGE));
        assert!(artifacts(&plan).is_empty(), "false artifact for {command}");
    }
    // A workspace publication publishes the workspace's package, which the
    // current directory's package.json does not name.
    let workspace = analyze("npm publish --workspace acme", Some(PACKAGE));
    assert!(artifacts(&workspace).iter().any(|(operation, identity)| {
        *operation == "artifact.publish_request"
            && matches!(identity, ResourceIdentity::Artifact { name, .. } if matches!(name.as_ref(), ResourceExpr::Unresolved { .. }))
    }));
    // npm keeps the last value of a repeated option, and reads an undefined
    // key as a boolean that leaves the publication running.
    let repeated = analyze(
        "npm publish --registry https://a --registry https://b",
        None,
    );
    assert!(artifacts(&repeated).iter().any(|(operation, identity)| {
        *operation == "artifact.publish_request"
            && matches!(identity, ResourceIdentity::Artifact { endpoint, .. } if endpoint.as_ref() == &lit("https://b"))
    }));
    let undefined_key = analyze("npm publish package.tgz --unknown", None);
    assert!(
        undefined_key
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.publish")
    );
}

#[test]
fn registry_owners_preserve_actions_and_reject_incomplete_selection() {
    for (command, count) in [
        ("npm owner add alice left-pad", 1),
        (
            "npm author remove mallory left-pad --no-dry-run --no-json",
            1,
        ),
        ("npm owner rm mallory --otp=123456", 1),
        ("cargo owner --add alice --remove bob crate-name", 2),
        ("gem owner rack -a alice -rbob --key release", 2),
    ] {
        let plan = analyze(command, Some(PACKAGE));
        let changes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "artifact.owner_change")
            .collect();
        assert_eq!(changes.len(), count, "{command}");
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::ENVIRONMENT_CONFIGURATION
            }),
            "{command}"
        );
        assert!(
            changes
                .iter()
                .all(|effect| effect.attributes.contains_key("principal")
                    && effect.attributes.contains_key("action")
                    && effect.attributes.get("active")
                        == Some(&effinterp_proto::AttrValue::Bool(true))
                    && effect.attributes.get("dry_run")
                        == Some(&effinterp_proto::AttrValue::Bool(false)))
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "artifact.delete")
        );
        for effect in &changes {
            assert_eq!(
                effect.attributes.get("scope"),
                Some(&effinterp_proto::AttrValue::String("whole".into()))
            );
            if command.starts_with("npm") {
                assert!(
                    matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::Artifact { ecosystem: ArtifactEcosystem::Npm, name, reference, .. } }
                    if matches!(name.as_ref(), ResourceExpr::Literal { .. }) && matches!(reference.as_ref(), ArtifactReference::Whole {}))
                );
            }
        }
        if count == 2 {
            for (action, principal) in [("add", "alice"), ("remove", "bob")] {
                assert!(changes.iter().any(|effect| effect.attributes.get("action")
                    == Some(&effinterp_proto::AttrValue::String(action.into()))
                    && effect.attributes.get("principal")
                        == Some(&effinterp_proto::AttrValue::String(principal.into()))));
            }
        }
    }
    let npm_dry_run = analyze("npm owner add alice left-pad --dry-run", Some(PACKAGE));
    assert!(npm_dry_run.effects.iter().any(|effect| {
        effect.operation.as_str() == "artifact.owner_change"
            && effect.attributes.get("active") == Some(&effinterp_proto::AttrValue::Bool(true))
            && effect.attributes.get("dry_run") == Some(&effinterp_proto::AttrValue::Bool(false))
    }));
    let missing_package = analyze("npm owner add alice", None);
    assert!(
        missing_package
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == effinterp_proto::BoundaryReason::MODEL_COVERAGE })
    );
    // npm reads an undefined configuration key as a boolean and still runs
    // the owner change.
    let undefined_key = analyze("npm owner rm alice left-pad --unknown", None);
    assert!(
        undefined_key
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "artifact.owner_change")
    );
    for command in [
        "npm owner rm",
        "cargo owner --list crate-name",
        "cargo owner --add",
        "cargo owner --remove --registry crates-io",
        "cargo owner --add alice crate-name --dry-run",
        "gem owner rack",
        "gem owner rack --add",
        "gem owner rack -a alice --dry-run",
        "gem owner rack -a alice --unknown",
        "gem owner -a alice",
    ] {
        let plan = analyze(command, None);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "artifact.owner_change"),
            "{command}"
        );
        assert!(!plan.boundaries.is_empty(), "{command}");
    }
    let owners = analyze("npm owner ls left-pad", None);
    assert!(owners.boundaries.is_empty());
    assert!(
        owners
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "network.request")
    );
    let plan = analyze("npm unpublish left-pad@1.3.0 --dry-run", None);
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "network.request")
    );
    assert!(!plan.effects.iter().any(|effect| matches!(
        effect.operation.as_str(),
        "artifact.delete" | "artifact.remove_request"
    )));
    assert!(!plan.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("publication hooks"))
    }));

    for command in [
        "npm install --save-dev typescript",
        "npm pack",
        "npm publish --dry-run",
        "npm publish --help",
        "npm unpublish left-pad --help",
        "npm owner ls left-pad",
        "gem owner rack",
    ] {
        let plan = analyze(command, None);
        assert!(
            !plan.effects.iter().any(|effect| matches!(
                effect.operation.as_str(),
                "artifact.publish"
                    | "artifact.publish_request"
                    | "artifact.delete"
                    | "artifact.remove_request"
                    | "artifact.owner_change"
            )),
            "false registry mutation: {command}"
        );
    }

    let install = analyze("npm install --save-dev typescript", None);
    assert!(install.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.write"
            && effect.attributes.get("disclosure")
                == Some(&effinterp_proto::AttrValue::String("contents".into()))
    }));
}

#[test]
fn gem_yank_attached_version() {
    let plan = analyze("gem yank example -v1.2.3 -v1.2.3", None);
    assert!(
        plan.effects.iter().any(
            |effect| effect.operation.as_str() == "artifact.yank_request"
                && effect.attributes.get("version")
                    == Some(&effinterp_proto::AttrValue::String("1.2.3".into()))
        ),
        "an attached short version value selects the yanked version"
    );
}

#[test]
fn npm_repeated_boolean_last_wins() {
    let unpublish = analyze("npm unpublish api@1.2.3 --dry-run --no-dry-run", None);
    assert!(
        artifacts(&unpublish)
            .iter()
            .any(|(operation, _)| *operation == "artifact.delete"),
        "the later --no-dry-run makes the unpublish real"
    );
    let dry = analyze("npm unpublish api@1.2.3 --no-dry-run --dry-run", None);
    assert!(artifacts(&dry).is_empty());
}

#[test]
fn pnpm_dlx_package_option() {
    // `--package` selects packages only before `dlx`; pnpm stops parsing its
    // options there, so after it the word is the package operand.
    for (command, owner_change) in [
        ("pnpm --package npm dlx npm owner add alice left-pad", true),
        ("pnpm dlx --package=npm npm owner add alice left-pad", false),
    ] {
        let plan = analyze(command, None);
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "artifact.owner_change"),
            owner_change,
            "{command}"
        );
    }
}
