//! Selects active extensions for visible invocations; it does not spawn processes.

use nah_proto::action::{ActionStream, EffectKind, InvocationEffect};
use nah_proto::ctx::{AbsolutePath, ActivationProjection, Ctx, GuardScope, Platform};
use nah_proto::exec_v1::ExecV1Request;
use nah_proto::observation::{Observation, ObservationValue};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::bundle::{ActiveExtensionCatalog, ExtensionBundle};

pub fn request(
    action_stream: &ActionStream,
    observation: &Observation,
) -> Result<ExecV1Request, String> {
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
    ExecV1Request::new(
        action_stream.clone(),
        cwd.ok_or_else(|| "missing-cwd".to_owned())?,
        roots.ok_or_else(|| "missing-roots".to_owned())?,
    )
    .map_err(|error| error.to_string())
}

pub(crate) fn selected_extensions<'a>(
    catalog: &'a ActiveExtensionCatalog,
    ctx: &Ctx,
    action_stream: &ActionStream,
) -> Vec<&'a ExtensionBundle> {
    catalog
        .extensions()
        .iter()
        .filter(|extension| matches_activation(extension.projection(), ctx, action_stream))
        .collect()
}

fn matches_activation(
    activation: &ActivationProjection,
    ctx: &Ctx,
    action_stream: &ActionStream,
) -> bool {
    action_stream
        .effects()
        .iter()
        .filter_map(|effect| match effect.kind() {
            EffectKind::Invocation { invocation } => Some(invocation),
            _ => None,
        })
        .any(|invocation| {
            matches_program(activation, invocation, ctx.platform())
                && matches_root(activation, ctx, invocation.cwd())
        })
}

fn matches_program(
    extension: &ActivationProjection,
    invocation: &InvocationEffect,
    platform: Platform,
) -> bool {
    let program = invocation.program();
    let standard_name = standard_program_name(program, platform);
    extension.match_programs().iter().any(|selector| {
        selector == program
            || standard_name
                .as_deref()
                .is_some_and(|name| selector_matches_standard(selector, name, platform))
    })
}

fn matches_root(
    extension: &ActivationProjection,
    ctx: &Ctx,
    invocation_cwd: Option<&AbsolutePath>,
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
    invocation_cwd.is_some_and(|cwd| {
        path_contains(trusted_root.path().as_str(), cwd.as_str(), ctx.platform())
    })
}

fn standard_program_name(program: &str, platform: Platform) -> Option<String> {
    match platform {
        Platform::Linux | Platform::Macos => {
            let (parent, name) = program.rsplit_once('/')?;
            let standard = matches!(
                parent,
                "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin" | "/usr/local/bin" | "/usr/local/sbin"
            ) || platform == Platform::Macos
                && matches!(parent, "/opt/homebrew/bin" | "/opt/homebrew/sbin");
            (standard && !name.is_empty()).then(|| name.to_owned())
        }
        Platform::Windows => {
            let normalized = program.replace('\\', "/");
            let (parent, name) = normalized.rsplit_once('/')?;
            let standard = matches!(
                parent.to_ascii_lowercase().as_str(),
                "c:/windows" | "c:/windows/system32"
            );
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

fn path_contains(root: &str, candidate: &str, platform: Platform) -> bool {
    let (root, candidate) = if platform == Platform::Windows {
        (root.to_ascii_lowercase(), candidate.to_ascii_lowercase())
    } else {
        (root.to_owned(), candidate.to_owned())
    };
    if root == candidate {
        return true;
    }
    let root = root.trim_end_matches(['/', '\\']);
    candidate.strip_prefix(root).is_some_and(|suffix| {
        root.is_empty() || suffix.starts_with('/') || suffix.starts_with('\\')
    })
}

pub(crate) fn memo_key(request: &ExecV1Request, ctx: &Ctx, extension: &ExtensionBundle) -> String {
    #[derive(Serialize)]
    struct RelevantCtx<'a> {
        activation: &'a ActivationProjection,
        #[serde(skip_serializing_if = "Option::is_none")]
        trusted_root: Option<&'a AbsolutePath>,
    }

    let trusted_root = extension
        .projection()
        .identity()
        .trusted_root()
        .and_then(|identity| {
            ctx.trust()
                .trusted_roots()
                .iter()
                .find(|root| root.identity() == identity)
                .map(|root| root.path())
        });
    let relevant_ctx = RelevantCtx {
        activation: extension.projection(),
        trusted_root,
    };
    let mut hash = Sha256::new();
    hash.update(b"nah-exec-v1-memo-key\0");
    for bytes in [
        serde_json::to_vec(request).expect("validated exec request serializes"),
        serde_json::to_vec(&relevant_ctx).expect("validated extension context serializes"),
        extension
            .projection()
            .bundle_hash()
            .as_str()
            .as_bytes()
            .to_vec(),
        ctx.policy_version().value().to_be_bytes().to_vec(),
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use nah_proto::action::{
        ActionStream, Coverage, EffectKind, FilesystemOperation, InvocationInput,
    };
    use nah_proto::ctx::{
        ActivationProjection, ContentHash, ExecProtocolVersion, GuardIdentity, PolicyVersion,
        SchemaVersion, TrustProjection, TrustedRoot, TrustedRootId,
    };

    use super::*;

    #[test]
    fn bare_selector_matches_only_bare_or_standard_path_invocations() {
        let activation = user_activation("aws", &["aws"]);
        let ctx = context(Platform::Linux, vec![activation.clone()], vec![]);

        for program in ["aws", "/bin/aws", "/usr/bin/aws", "/usr/local/bin/aws"] {
            assert!(
                matches_activation(&activation, &ctx, &stream(&[(program, None)])),
                "{program}"
            );
        }
        for lookalike in ["./aws", "/tmp/aws", "/repo/bin/aws", "/usr/bin/../tmp/aws"] {
            assert!(
                !matches_activation(&activation, &ctx, &stream(&[(lookalike, None)])),
                "{lookalike}"
            );
        }

        let exact = user_activation("exact", &["/tmp/aws"]);
        assert!(matches_activation(
            &exact,
            &context(Platform::Linux, vec![exact.clone()], vec![]),
            &stream(&[("/tmp/aws", None)])
        ));
    }

    #[test]
    fn standard_path_aliases_are_platform_specific() {
        let activation = user_activation("aws", &["aws"]);
        let macos = context(Platform::Macos, vec![activation.clone()], vec![]);
        assert!(matches_activation(
            &activation,
            &macos,
            &stream(&[("/opt/homebrew/bin/aws", None)])
        ));

        let windows = context(Platform::Windows, vec![activation.clone()], vec![]);
        assert!(matches_activation(
            &activation,
            &windows,
            &stream(&[(r"C:\Windows\System32\AWS.EXE", None)])
        ));
        assert!(!matches_activation(
            &activation,
            &windows,
            &stream(&[(r"C:\tools\aws.exe", None)])
        ));
    }

    #[test]
    fn project_selection_uses_the_matching_invocations_visible_cwd() {
        let root_id = TrustedRootId::new("root-1").unwrap();
        let activation = ActivationProjection::new(
            GuardIdentity::project(root_id.clone(), "deploy-guard").unwrap(),
            ContentHash::new("b".repeat(64)).unwrap(),
            ExecProtocolVersion::V1,
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
            stream(&[("other", Some("/repo")), ("deploy", Some("/outside"))]);
        assert!(!matches_activation(
            &activation,
            &ctx,
            &unrelated_inside_and_match_outside
        ));
        assert!(!matches_activation(
            &activation,
            &ctx,
            &stream(&[("deploy", Some("/repository"))])
        ));
        assert!(!matches_activation(
            &activation,
            &ctx,
            &stream(&[("deploy", None)])
        ));
        assert!(matches_activation(
            &activation,
            &ctx,
            &stream(&[("deploy", Some("/repo/subdir"))])
        ));
    }

    #[test]
    fn unresolved_filesystem_effects_preserve_invocation_based_selection() {
        let activation = user_activation("rm-guard", &["rm"]);
        let ctx = context(Platform::Linux, vec![activation.clone()], vec![]);
        let invocation = EffectKind::known_with_input(
            "rm",
            "delete",
            InvocationInput::shell(
                "rm",
                vec!["rm".into(), "-rf".into(), "${TARGET}".into()],
                None,
            ),
        )
        .unwrap();
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                invocation,
                EffectKind::FilesystemUnresolved {
                    operation: FilesystemOperation::Delete,
                    recursive: true,
                },
            ]],
            vec![],
        )
        .unwrap();

        assert!(matches_activation(&activation, &ctx, &stream));
    }

    fn user_activation(name: &str, programs: &[&str]) -> ActivationProjection {
        ActivationProjection::new(
            GuardIdentity::user(name).unwrap(),
            ContentHash::new("a".repeat(64)).unwrap(),
            ExecProtocolVersion::V1,
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
            SchemaVersion::V1,
            platform,
            AbsolutePath::new(platform, home).unwrap(),
            vec![],
            activations,
            TrustProjection::new(roots).unwrap(),
            PolicyVersion::V1,
        )
        .unwrap()
    }

    fn stream(invocations: &[(&str, Option<&str>)]) -> ActionStream {
        let stages = invocations
            .iter()
            .map(|(program, cwd)| {
                let invocation = EffectKind::known(program, "read-only").unwrap();
                let invocation = match cwd {
                    Some(cwd) => {
                        let platform = if cwd.as_bytes().get(1) == Some(&b':') {
                            Platform::Windows
                        } else {
                            Platform::Linux
                        };
                        invocation.with_invocation_cwd(AbsolutePath::new(platform, *cwd).unwrap())
                    }
                    None => invocation,
                };
                vec![invocation]
            })
            .collect();
        ActionStream::new(Coverage::Full, stages, vec![]).unwrap()
    }
}
