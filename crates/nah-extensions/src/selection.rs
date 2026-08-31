//! Selects active extensions for visible invocations; it does not spawn processes.

use nah_proto::action::{ActionStream, EffectKind, InvocationEffect};
use nah_proto::ctx::{AbsolutePath, ActivationProjection, Ctx, GuardScope, Platform};
use nah_proto::exec_v1::ExecV1Request;
use nah_proto::observation::{Observation, ObservationValue};
#[cfg(feature = "effinterp")]
use nah_proto::stream::{
    ActionStream as EffinterpActionStream, ExecRequest as EffinterpExecRequest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::bundle::{ActiveExtensionCatalog, ExtensionBundle};

#[cfg(not(feature = "effinterp"))]
pub fn request(
    action_stream: &ActionStream,
    observation: &Observation,
) -> Result<ExecV1Request, String> {
    let (cwd, roots) = request_observation(observation)?;
    ExecV1Request::new(action_stream.clone(), cwd, roots).map_err(|error| error.to_string())
}

#[cfg(feature = "effinterp")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ExtensionExecRequest {
    Legacy(ExecV1Request),
    Effinterp(Box<EffinterpExecRequest>),
}

#[cfg(feature = "effinterp")]
pub fn request(
    action_stream: &ActionStream,
    effinterp_action_stream: Option<&EffinterpActionStream>,
    observation: &Observation,
) -> Result<ExtensionExecRequest, String> {
    let (cwd, roots) = request_observation(observation)?;
    match effinterp_action_stream {
        Some(stream) => EffinterpExecRequest::new(stream.clone(), cwd, roots)
            .map(|request| ExtensionExecRequest::Effinterp(Box::new(request))),
        None => {
            ExecV1Request::new(action_stream.clone(), cwd, roots).map(ExtensionExecRequest::Legacy)
        }
    }
    .map_err(|error| error.to_string())
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

#[cfg(not(feature = "effinterp"))]
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

#[cfg(feature = "effinterp")]
pub(crate) fn selected_extensions<'a>(
    catalog: &'a ActiveExtensionCatalog,
    ctx: &Ctx,
    action_stream: &ActionStream,
    effinterp_action_stream: Option<&EffinterpActionStream>,
) -> Vec<&'a ExtensionBundle> {
    catalog
        .extensions()
        .iter()
        .filter(|extension| match effinterp_action_stream {
            Some(stream) => matches_effinterp_activation(extension.projection(), ctx, stream),
            None => matches_activation(extension.projection(), ctx, action_stream),
        })
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

#[cfg(feature = "effinterp")]
fn matches_effinterp_activation(
    activation: &ActivationProjection,
    ctx: &Ctx,
    action_stream: &EffinterpActionStream,
) -> bool {
    action_stream.plan().effects.iter().any(|effect| {
        let nah_proto::stream::effinterp_proto::ResourceExpr::Concrete {
            identity:
                nah_proto::stream::effinterp_proto::ResourceIdentity::Process {
                    executable, cwd, ..
                },
        } = &effect.resource
        else {
            return false;
        };
        let cwd = cwd.as_deref().and_then(|cwd| match cwd {
            nah_proto::stream::effinterp_proto::ResourceExpr::Concrete {
                identity: nah_proto::stream::effinterp_proto::ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        });
        matches_program_name(activation, executable, ctx.platform())
            && matches_root_path(activation, ctx, cwd)
    })
}

fn matches_program(
    extension: &ActivationProjection,
    invocation: &InvocationEffect,
    platform: Platform,
) -> bool {
    matches_program_name(extension, invocation.program(), platform)
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

fn matches_root(
    extension: &ActivationProjection,
    ctx: &Ctx,
    invocation_cwd: Option<&AbsolutePath>,
) -> bool {
    matches_root_path(extension, ctx, invocation_cwd.map(AbsolutePath::as_str))
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

#[cfg(not(feature = "effinterp"))]
pub(crate) fn memo_key(request: &ExecV1Request, ctx: &Ctx, extension: &ExtensionBundle) -> String {
    memo_key_for(request, b"action-stream-v1\0", ctx, extension)
}

#[cfg(feature = "effinterp")]
pub(crate) fn memo_key(
    request: &ExtensionExecRequest,
    ctx: &Ctx,
    extension: &ExtensionBundle,
) -> String {
    let shape = match request {
        ExtensionExecRequest::Legacy(_) => b"action-stream-v1\0".as_slice(),
        ExtensionExecRequest::Effinterp(_) => b"effinterp-action-stream-v1\0".as_slice(),
    };
    memo_key_for(request, shape, ctx, extension)
}

fn memo_key_for(
    request: &impl Serialize,
    shape: &[u8],
    ctx: &Ctx,
    extension: &ExtensionBundle,
) -> String {
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
    hash.update(shape);
    for bytes in [
        serde_json::to_vec(request).expect("validated exec request serializes"),
        serde_json::to_vec(&relevant_ctx).expect("validated extension context serializes"),
        extension
            .projection()
            .bundle_hash()
            .as_str()
            .as_bytes()
            .to_vec(),
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
            platform,
            AbsolutePath::new(platform, home).unwrap(),
            vec![],
            activations,
            TrustProjection::new(roots).unwrap(),
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
