//! Selects active extensions for visible invocations; it does not spawn processes.

use crate::bundle::{ActiveExtensionCatalog, ExtensionBundle};
use nah_proto::ctx::{AbsolutePath, ActivationProjection, Ctx, GuardScope, Platform};
use nah_proto::effects::{GuardEvidence, Knowledge};
use nah_proto::exec_v2::ExecV2Request;
use nah_proto::labels::lexical_path::fold;
use nah_proto::labels::standard_executable_directory;
use nah_proto::observation::{Observation, ObservationValue};

/// Builds the exec/v2 request a custom guard reads on stdin from the call's
/// evidence and its observed cwd and roots.
pub fn exec_request(
    evidence: &GuardEvidence,
    observation: &Observation,
) -> Result<ExecV2Request, String> {
    let (cwd, roots) = request_observation(observation)?;
    ExecV2Request::new(evidence, cwd, roots).map_err(|error| error.to_string())
}

fn request_observation(
    observation: &Observation,
) -> Result<
    (
        nah_proto::observation::Observed<AbsolutePath>,
        nah_proto::observation::Observed<Vec<nah_proto::observation::Root>>,
    ),
    String,
> {
    let cwd = observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Cwd { observed } => Some(observed.clone()),
            _ => None,
        });
    let roots = observation
        .facts()
        .iter()
        .find_map(|fact| match fact.value() {
            ObservationValue::Roots { observed } => Some(observed.clone()),
            _ => None,
        });
    Ok((
        cwd.ok_or_else(|| "missing-cwd".to_owned())?,
        roots.ok_or_else(|| "missing-roots".to_owned())?,
    ))
}

/// Selects the active custom guards whose activation matches a visible call.
/// Unsupported: calls launched from interpreter source (source-internal calls)
/// never select a custom guard; only `GuardEvidence::public_calls` are matched.
pub(crate) fn selected_extensions<'a>(
    catalog: &'a ActiveExtensionCatalog,
    ctx: &Ctx,
    evidence: &GuardEvidence,
) -> Vec<&'a ExtensionBundle> {
    catalog
        .extensions()
        .iter()
        .filter(|extension| matches_activation(extension.projection(), ctx, evidence))
        .collect()
}

fn matches_activation(
    activation: &ActivationProjection,
    ctx: &Ctx,
    evidence: &GuardEvidence,
) -> bool {
    evidence.public_calls().any(|call| {
        let Knowledge::Known(program) = &call.identity else {
            return false;
        };
        let cwd = match &call.cwd {
            Knowledge::Known(path) => Some(path.as_str()),
            Knowledge::Unknown => None,
        };
        matches_program_name(activation, program, ctx.platform())
            && matches_root_path(activation, ctx, cwd)
    })
}

fn matches_program_name(
    extension: &ActivationProjection,
    program: &str,
    platform: Platform,
) -> bool {
    let standard_name = standard_program_name(program, platform);
    extension.match_programs().iter().any(|selector| {
        selector == program
            || standard_name
                .as_deref()
                .is_some_and(|name| selector_matches_standard(selector, name, platform))
    })
}

fn matches_root_path(
    extension: &ActivationProjection,
    ctx: &Ctx,
    invocation_cwd: Option<&str>,
) -> bool {
    if extension.identity().scope() == GuardScope::User {
        return true;
    }
    let Some(trusted_root_id) = extension.identity().trusted_root() else {
        return false;
    };
    let Some(trusted_root) = ctx
        .trust()
        .trusted_roots()
        .iter()
        .find(|root| root.identity() == trusted_root_id)
    else {
        return false;
    };
    invocation_cwd
        .is_some_and(|cwd| path_contains(trusted_root.path().as_str(), cwd, ctx.platform()))
}

fn standard_program_name(program: &str, platform: Platform) -> Option<String> {
    match platform {
        Platform::Linux | Platform::Macos => {
            let (parent, name) = program.rsplit_once('/')?;
            let standard = standard_executable_directory(parent, platform);
            (standard && !name.is_empty()).then(|| name.to_owned())
        }
        Platform::Windows => {
            let normalized = program.replace('\\', "/");
            let (parent, name) = normalized.rsplit_once('/')?;
            let standard = standard_executable_directory(parent, platform);
            standard
                .then(|| name.to_ascii_lowercase())
                .map(|name| name.strip_suffix(".exe").unwrap_or(&name).to_owned())
                .filter(|name| !name.is_empty())
        }
    }
}

fn selector_matches_standard(selector: &str, name: &str, platform: Platform) -> bool {
    if selector.contains(['/', '\\']) {
        return false;
    }
    match platform {
        Platform::Linux | Platform::Macos => selector == name,
        Platform::Windows => selector
            .strip_suffix(".exe")
            .or_else(|| selector.strip_suffix(".EXE"))
            .unwrap_or(selector)
            .eq_ignore_ascii_case(name),
    }
}

/// Whether an invocation cwd is a trusted root or under it. Intentionally not
/// `lexical_path::contains`: a root spelled with a trailing separator does not
/// contain its own unslashed spelling here, and a `/` root contains every cwd,
/// including a Windows drive path. Switching would change which trusted-root
/// extensions run.
fn path_contains(root: &str, candidate: &str, platform: Platform) -> bool {
    let (root, candidate) = (fold(root, platform), fold(candidate, platform));
    if root == candidate {
        return true;
    }
    let root = root.trim_end_matches('/');
    candidate
        .strip_prefix(root)
        .is_some_and(|suffix| root.is_empty() || suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use nah_proto::action::Coverage;
    use nah_proto::ctx::{
        ActivationProjection, ContentHash, ExecProtocolVersion, GuardIdentity, TrustProjection,
        TrustedRoot, TrustedRootId,
    };

    use super::*;

    #[test]
    fn bare_selector_matches_only_bare_or_standard_path_invocations() {
        let activation = user_activation("aws", &["aws"]);
        let ctx = context(Platform::Linux, vec![activation.clone()], vec![]);

        for program in ["aws", "/bin/aws", "/usr/bin/aws", "/usr/local/bin/aws"] {
            assert!(
                matches_activation(
                    &activation,
                    &ctx,
                    &visible_call_evidence(&[(program, None)])
                ),
                "{program}"
            );
        }
        for lookalike in ["./aws", "/tmp/aws", "/repo/bin/aws", "/usr/bin/../tmp/aws"] {
            assert!(
                !matches_activation(
                    &activation,
                    &ctx,
                    &visible_call_evidence(&[(lookalike, None)])
                ),
                "{lookalike}"
            );
        }

        let exact = user_activation("exact", &["/tmp/aws"]);
        assert!(matches_activation(
            &exact,
            &context(Platform::Linux, vec![exact.clone()], vec![]),
            &visible_call_evidence(&[("/tmp/aws", None)])
        ));
    }

    #[test]
    fn standard_path_aliases_are_platform_specific() {
        let activation = user_activation("aws", &["aws"]);
        let macos = context(Platform::Macos, vec![activation.clone()], vec![]);
        assert!(matches_activation(
            &activation,
            &macos,
            &visible_call_evidence(&[("/opt/homebrew/bin/aws", None)])
        ));

        let windows = context(Platform::Windows, vec![activation.clone()], vec![]);
        assert!(matches_activation(
            &activation,
            &windows,
            &visible_call_evidence(&[(r"C:\Windows\System32\AWS.EXE", None)])
        ));
        assert!(!matches_activation(
            &activation,
            &windows,
            &visible_call_evidence(&[(r"C:\tools\aws.exe", None)])
        ));
    }

    #[test]
    fn project_selection_uses_the_matching_invocations_visible_cwd() {
        let root_id = TrustedRootId::new("root-1").unwrap();
        let activation = ActivationProjection::new(
            GuardIdentity::project(root_id.clone(), "deploy-guard").unwrap(),
            ContentHash::new("b".repeat(64)).unwrap(),
            ExecProtocolVersion::V2,
            vec!["deploy".into()],
        )
        .unwrap();
        let ctx = context(
            Platform::Linux,
            vec![activation.clone()],
            vec![TrustedRoot::new(
                root_id,
                AbsolutePath::new(Platform::Linux, "/repo").unwrap(),
            )],
        );

        let unrelated_inside_and_match_outside =
            visible_call_evidence(&[("other", Some("/repo")), ("deploy", Some("/outside"))]);
        assert!(!matches_activation(
            &activation,
            &ctx,
            &unrelated_inside_and_match_outside
        ));
        assert!(!matches_activation(
            &activation,
            &ctx,
            &visible_call_evidence(&[("deploy", Some("/repository"))])
        ));
        assert!(!matches_activation(
            &activation,
            &ctx,
            &visible_call_evidence(&[("deploy", None)])
        ));
        assert!(!matches_activation(
            &activation,
            &ctx,
            &visible_call_evidence(&[("deploy", Some(r"/repo\outside"))])
        ));
        assert!(matches_activation(
            &activation,
            &ctx,
            &visible_call_evidence(&[("deploy", Some("/repo/subdir"))])
        ));
    }

    #[test]
    fn unresolved_filesystem_effects_preserve_invocation_based_selection() {
        let activation = user_activation("rm-guard", &["rm"]);
        let ctx = context(Platform::Linux, vec![activation.clone()], vec![]);
        // `rm -rf "${TARGET}"`: the delete target is unresolved, so the call's
        // arguments are unknown and coverage is partial.
        let evidence = evidence(Coverage::Partial, &[("rm", None, None)]);

        assert!(matches_activation(&activation, &ctx, &evidence));
    }

    /// A visible call: its program, argv and working directory when known.
    type Call<'a> = (&'a str, Option<Vec<String>>, Option<AbsolutePath>);

    fn evidence(coverage: Coverage, calls: &[Call<'_>]) -> GuardEvidence {
        use Knowledge::{Known, Unknown};
        use nah_proto::effects::*;
        let calls = calls
            .iter()
            .enumerate()
            .map(|(i, (program, argv, cwd))| EffectCall {
                arguments: argv.clone().map_or(Unknown, Known),
                id: CallId(i as u32),
                parent: None,
                kind: InvocationKind::Argv,
                identity: Known((*program).into()),
                input: None,
                hidden_characters: false,
                cwd: cwd.clone().map_or(Unknown, Known),
                payload_group: Known(PayloadGroupId(0)),
                visibility_ordinal: Known(i as u32),
                coverage,
            })
            .collect();
        let graph = EffectGraph {
            calls,
            resources: vec![],
            facts: vec![],
            occurrences: vec![],
            relations: vec![],
            conditions: vec![],
            coverage: vec![],
            gaps: vec![],
            causality: CausalAvailability::Unavailable,
        };
        let public = PublicSelection::visible(&graph);
        GuardEvidence::new(graph, public).unwrap()
    }
    fn user_activation(name: &str, programs: &[&str]) -> ActivationProjection {
        ActivationProjection::new(
            GuardIdentity::user(name).unwrap(),
            ContentHash::new("a".repeat(64)).unwrap(),
            ExecProtocolVersion::V2,
            programs
                .iter()
                .map(|program| (*program).to_owned())
                .collect(),
        )
        .unwrap()
    }

    fn context(
        platform: Platform,
        activations: Vec<ActivationProjection>,
        roots: Vec<TrustedRoot>,
    ) -> Ctx {
        let home = match platform {
            Platform::Windows => r"C:\Users\test",
            Platform::Linux | Platform::Macos => "/home/test",
        };
        Ctx::new(
            platform,
            AbsolutePath::new(platform, home).unwrap(),
            vec![],
            activations,
            TrustProjection::new(roots).unwrap(),
        )
        .unwrap()
    }

    fn visible_call_evidence(invocations: &[(&str, Option<&str>)]) -> GuardEvidence {
        let calls: Vec<_> = invocations
            .iter()
            .map(|(program, cwd)| {
                let cwd = cwd.map(|cwd| {
                    let platform = if cwd.as_bytes().get(1) == Some(&b':') {
                        Platform::Windows
                    } else {
                        Platform::Linux
                    };
                    AbsolutePath::new(platform, cwd).unwrap()
                });
                (*program, Some(vec![(*program).to_owned()]), cwd)
            })
            .collect();
        evidence(Coverage::Full, &calls)
    }
}
