//! Function summaries: a reusable, language-neutral description of one
//! function's effect behavior expressed in terms of its parameters. Applying a
//! summary at a call site substitutes the caller's argument expressions for the
//! parameters, so `def wipe(root, t): rmtree(join(root, t))` summarizes to
//! `filesystem.delete join(param root, param t)` and a call `wipe("/tmp", name)`
//! specializes it to `filesystem.delete join("/tmp", param name)`.
//!
//! The summary layer is what lets repository analysis follow calls into user
//! code — within a file now, across files once summaries are indexed — without
//! re-walking a callee's body at every call site.

use std::collections::HashMap;

use effinterp_proto::{
    Boundary, ContainerStorage, CoverageLevel, Domain, Effect, ResourceExpr, ResourceIdentity,
};

use crate::SemanticValue;
use crate::builder::PlanBuilder;
use crate::resource_transfer::TransferBinding;

/// A summary of a function's externally visible effect behavior. Resource
/// expressions in `effects` and `returns` may reference the function's
/// parameters via [`ResourceExpr::Parameter`]; those are the substitution
/// points.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    /// Parameter names, in declaration order.
    pub params: Vec<String>,
    /// Effects the function may produce, parameterized by `params`.
    pub effects: Vec<Effect>,
    /// Promoted model revisions that own each effect, aligned with `effects`.
    pub effect_models: Vec<Vec<String>>,
    /// Source-to-destination transfer pairings among `effects`, by slot. They
    /// are recorded where the transfer is lowered and replayed at every call
    /// site, so a helper that copies or renames keeps its pairing after
    /// argument substitution.
    pub transfers: Vec<TransferBinding>,
    /// The function's return value as a resource expression in terms of
    /// `params`, when statically derivable (e.g. a path-building helper).
    pub returns: Option<SemanticValue>,
    /// Opaque boundaries within the function (unresolved calls, dynamic code).
    pub boundaries: Vec<Boundary>,
    /// Coverage the function contributes, by domain.
    pub coverage: Vec<(Domain, CoverageLevel)>,
    /// The body's control flow over `effects` and the callable's call edges,
    /// which decides the occurrences every successful completion reaches.
    pub control_flow: crate::control_flow::ControlFlow,
}

impl Summary {
    pub fn pure() -> Self {
        Self {
            params: Vec::new(),
            effects: Vec::new(),
            effect_models: Vec::new(),
            transfers: Vec::new(),
            returns: None,
            boundaries: Vec::new(),
            coverage: Vec::new(),
            control_flow: crate::control_flow::ControlFlow::widened(),
        }
    }
}

/// Re-record a summary's transfer pairings against the effect slots its
/// effects landed in. A pairing whose endpoint effect was refused (a saturated
/// limit, an unregistered operation) contributes nothing rather than a
/// fabricated pair.
pub(crate) fn replay_transfers(
    builder: &mut PlanBuilder,
    transfers: &[TransferBinding],
    slots: &[Option<u32>],
) {
    for binding in transfers {
        let (Some(Some(source)), Some(Some(destination))) = (
            slots.get(binding.source as usize),
            slots.get(binding.destination as usize),
        ) else {
            continue;
        };
        builder.transfer_binding(TransferBinding::new(*source, *destination));
    }
}

/// Substitute argument expressions for parameter references throughout a
/// resource expression. A parameter with no binding stays symbolic (it is a
/// free parameter of the enclosing scope), so partial application widens
/// rather than inventing a value.
pub fn substitute_resource_expr(
    expr: &ResourceExpr,
    bindings: &HashMap<String, ResourceExpr>,
) -> ResourceExpr {
    match expr {
        ResourceExpr::Parameter { name } => match bindings.get(name) {
            Some(arg) => arg.clone(),
            None => expr.clone(),
        },
        ResourceExpr::Property { base, name } => ResourceExpr::Property {
            base: Box::new(substitute_resource_expr(base, bindings)),
            name: name.clone(),
        },
        ResourceExpr::Join { parts } => {
            let textual = parts.first().is_some_and(text_concat_marker);
            let parts: Vec<_> = parts
                .iter()
                .map(|p| substitute_resource_expr(p, bindings))
                .collect();
            if textual {
                refold_text_concat(parts)
            } else {
                ResourceExpr::Join { parts }
            }
        }
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives
                .iter()
                .map(|a| substitute_resource_expr(a, bindings))
                .collect(),
        },
        ResourceExpr::Concrete { identity } => ResourceExpr::Concrete {
            identity: substitute_identity(identity, bindings),
        },
        ResourceExpr::Literal { .. }
        | ResourceExpr::Environment { .. }
        | ResourceExpr::Pattern { .. }
        | ResourceExpr::Unresolved { .. } => expr.clone(),
    }
}

fn refold_text_concat(parts: Vec<ResourceExpr>) -> ResourceExpr {
    let mut text = String::new();
    let mut filesystem = false;
    for part in &parts {
        match part {
            ResourceExpr::Literal { value } => text.push_str(value),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => {
                filesystem = true;
                text.push_str(path);
            }
            _ => {
                return ResourceExpr::Join {
                    parts: parts
                        .into_iter()
                        .map(|part| match part {
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path },
                            } => ResourceExpr::Literal { value: path },
                            part => part,
                        })
                        .collect(),
                };
            }
        }
    }
    if !filesystem {
        return ResourceExpr::Join { parts };
    }
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: text },
    }
}

fn text_concat_marker(expr: &ResourceExpr) -> bool {
    matches!(expr, ResourceExpr::Literal { value } if value.is_empty())
}

// A leading empty literal distinguishes textual concatenation from path joins until substitution.
pub(crate) fn has_text_concat(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Join { parts } => {
            parts.first().is_some_and(text_concat_marker) || parts.iter().any(has_text_concat)
        }
        ResourceExpr::Union { alternatives } => alternatives.iter().any(has_text_concat),
        ResourceExpr::Property { base, .. } => has_text_concat(base),
        _ => false,
    }
}

/// Whether a resource expression contains an unresolved part anywhere in its
/// joins, unions or property bases.
pub(crate) fn contains_unresolved(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Unresolved { .. } => true,
        ResourceExpr::Join { parts } => parts.iter().any(contains_unresolved),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(contains_unresolved),
        ResourceExpr::Property { base, .. } => contains_unresolved(base),
        _ => false,
    }
}

fn substitute_identity(
    identity: &ResourceIdentity,
    bindings: &HashMap<String, ResourceExpr>,
) -> ResourceIdentity {
    if !identity.infrastructure_values().is_empty() {
        let mut result = identity.clone();
        for value in result.infrastructure_values_mut() {
            *value = substitute_resource_expr(value, bindings);
        }
        return result;
    }
    if let Some(scope) = identity.scope() {
        let mut result = identity.clone();
        *result.scope_mut().unwrap() = scope.map(|expr| substitute_resource_expr(expr, bindings));
        return result;
    }
    match identity {
        ResourceIdentity::Artifact {
            ecosystem,
            endpoint,
            name,
            reference,
        } => ResourceIdentity::Artifact {
            ecosystem: *ecosystem,
            endpoint: Box::new(substitute_resource_expr(endpoint, bindings)),
            name: Box::new(substitute_resource_expr(name, bindings)),
            reference: Box::new(reference.map(|value| substitute_resource_expr(value, bindings))),
        },
        ResourceIdentity::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => ResourceIdentity::GitRepository {
            worktree: worktree
                .as_ref()
                .map(|worktree| Box::new(substitute_resource_expr(worktree, bindings))),
            git_dir: git_dir
                .as_ref()
                .map(|git_dir| Box::new(substitute_resource_expr(git_dir, bindings))),
            pathspec: pathspec
                .as_ref()
                .map(|pathspec| Box::new(substitute_resource_expr(pathspec, bindings))),
        },
        ResourceIdentity::Process {
            executable,
            path,
            argv,
            cwd,
        } => ResourceIdentity::Process {
            executable: executable.clone(),
            path: path.clone(),
            argv: argv
                .iter()
                .map(|arg| substitute_resource_expr(arg, bindings))
                .collect(),
            cwd: cwd
                .as_ref()
                .map(|cwd| Box::new(substitute_resource_expr(cwd, bindings))),
        },
        ResourceIdentity::Container {
            runtime,
            name,
            image,
            storage,
        } => ResourceIdentity::Container {
            runtime: runtime.clone(),
            name: name.clone(),
            image: image.clone(),
            storage: storage
                .iter()
                .map(|storage| match storage {
                    ContainerStorage::BindMount {
                        host_path,
                        container_path,
                        read_only,
                    } => ContainerStorage::BindMount {
                        host_path: substitute_resource_expr(host_path, bindings),
                        container_path: substitute_resource_expr(container_path, bindings),
                        read_only: *read_only,
                    },
                    ContainerStorage::Volume {
                        name,
                        container_path,
                    } => ContainerStorage::Volume {
                        name: name.clone(),
                        container_path: substitute_resource_expr(container_path, bindings),
                    },
                })
                .collect(),
        },
        identity => identity.clone(),
    }
}

/// Bind a summary's parameters positionally to caller argument expressions.
/// Extra parameters (fewer args than params) stay free/symbolic.
pub(crate) fn bind_positional(
    params: &[String],
    args: &[ResourceExpr],
) -> HashMap<String, ResourceExpr> {
    params
        .iter()
        .zip(args.iter())
        .map(|(p, a)| (p.clone(), a.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use effinterp_proto::{PathPlatform, ResourceIdentity, normalize_resource};

    fn param(name: &str) -> ResourceExpr {
        ResourceExpr::Parameter {
            name: name.to_string(),
        }
    }

    fn concrete_path(path: &str) -> ResourceExpr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: path.to_string(),
            },
        }
    }

    #[test]
    fn substitutes_parameters_in_a_join() {
        let expr = ResourceExpr::Join {
            parts: vec![param("root"), param("t")],
        };
        let bindings = bind_positional(
            &["root".into(), "t".into()],
            &[concrete_path("/tmp"), param("name")],
        );
        let out = substitute_resource_expr(&expr, &bindings);
        // root -> /tmp (concrete); t -> name (still symbolic, caller's param).
        assert_eq!(
            out,
            ResourceExpr::Join {
                parts: vec![concrete_path("/tmp"), param("name")],
            }
        );
    }

    #[test]
    fn composed_infrastructure_targets_bind_scope_without_losing_identity() {
        let literal = |value: &str| ResourceExpr::Literal {
            value: value.into(),
        };
        let bindings = HashMap::from([
            ("root".into(), concrete_path("/infra")),
            ("name".into(), literal("api")),
            ("namespace".into(), literal("prod")),
        ]);
        let managed = ResourceExpr::Concrete {
            identity: ResourceIdentity::ManagedInfrastructure {
                tool: "terraform".into(),
                configuration_root: Box::new(param("root")),
                workspace: Box::new(param("workspace")),
                resource_type: Some("aws_instance".into()),
                address: Some("aws_instance.web".into()),
                instance: Box::new(param("instance")),
            },
        };
        let ResourceExpr::Concrete {
            identity:
                ResourceIdentity::ManagedInfrastructure {
                    configuration_root,
                    workspace,
                    address,
                    ..
                },
        } = substitute_resource_expr(&managed, &bindings)
        else {
            panic!("managed identity lost");
        };
        assert_eq!(*configuration_root, concrete_path("/infra"));
        assert_eq!(*workspace, param("workspace"));
        assert_eq!(address.as_deref(), Some("aws_instance.web"));
        let kubernetes = ResourceExpr::Concrete {
            identity: ResourceIdentity::KubernetesResource {
                api_group: "apps".into(),
                kind: "Deployment".into(),
                name: Box::new(param("name")),
                namespace: effinterp_proto::KubernetesNamespace::Namespaced {
                    namespace: Box::new(param("namespace")),
                },
                server: Box::new(param("server")),
                context: Box::new(literal("west")),
            },
        };
        let ResourceExpr::Concrete {
            identity:
                ResourceIdentity::KubernetesResource {
                    name,
                    namespace: effinterp_proto::KubernetesNamespace::Namespaced { namespace },
                    server,
                    context,
                    ..
                },
        } = substitute_resource_expr(&kubernetes, &bindings)
        else {
            panic!("Kubernetes identity lost");
        };
        assert_eq!(*name, literal("api"));
        assert_eq!(*namespace, literal("prod"));
        assert_eq!(*server, param("server"));
        assert_eq!(*context, literal("west"));
    }

    #[test]
    fn artifact_namespace_and_reference_substitution_preserves_reference_kind() {
        use effinterp_proto::{ArtifactEcosystem, ArtifactReference};
        let expr = ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact {
                ecosystem: ArtifactEcosystem::Npm,
                endpoint: Box::new(param("registry")),
                name: Box::new(param("package")),
                reference: Box::new(ArtifactReference::Version {
                    value: param("version"),
                }),
            },
        };
        let value = |value: &str| ResourceExpr::Literal {
            value: value.into(),
        };
        let bindings = bind_positional(
            &["registry".into(), "package".into(), "version".into()],
            &[
                value("https://registry.example"),
                value("@acme/api"),
                value("1.2.3"),
            ],
        );
        assert_eq!(
            substitute_resource_expr(&expr, &bindings),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Artifact {
                    ecosystem: ArtifactEcosystem::Npm,
                    endpoint: Box::new(value("https://registry.example")),
                    name: Box::new(value("@acme/api")),
                    reference: Box::new(ArtifactReference::Version {
                        value: value("1.2.3")
                    }),
                }
            }
        );
    }

    #[test]
    fn substituted_join_keeps_the_concrete_base() {
        let expr = ResourceExpr::Join {
            parts: vec![param("root"), concrete_path("/data")],
        };
        let bindings = bind_positional(&["root".into()], &[concrete_path("/home/u")]);
        assert_eq!(
            normalize_resource(
                substitute_resource_expr(&expr, &bindings),
                PathPlatform::Posix
            ),
            concrete_path("/home/u/data")
        );
    }

    #[test]
    fn substituted_text_concat_does_not_insert_path_separators() {
        let expr = ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: String::new(),
                },
                ResourceExpr::Literal {
                    value: "/tmp/job-".into(),
                },
                param("id"),
                ResourceExpr::Literal {
                    value: ".log".into(),
                },
            ],
        };
        let bindings = bind_positional(&["id".into()], &[concrete_path("42")]);
        assert_eq!(
            substitute_resource_expr(&expr, &bindings),
            concrete_path("/tmp/job-42.log")
        );
        let expr = ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: String::new(),
                },
                param("root"),
                param("id"),
                param("suffix"),
            ],
        };
        let partial = substitute_resource_expr(
            &expr,
            &bind_positional(
                &["root".into(), "suffix".into()],
                &[concrete_path("/tmp/job-"), concrete_path(".log")],
            ),
        );
        let partial = normalize_resource(partial, PathPlatform::Posix);
        assert_eq!(
            partial,
            ResourceExpr::Join {
                parts: vec![
                    ResourceExpr::Literal {
                        value: String::new()
                    },
                    ResourceExpr::Literal {
                        value: "/tmp/job-".into()
                    },
                    param("id"),
                    ResourceExpr::Literal {
                        value: ".log".into()
                    },
                ]
            }
        );
        assert_eq!(
            normalize_resource(
                substitute_resource_expr(&partial, &bindings),
                PathPlatform::Posix
            ),
            concrete_path("/tmp/job-42.log")
        );
    }

    #[test]
    fn unmarked_literal_join_preserves_path_semantics() {
        let expr = ResourceExpr::Join {
            parts: vec![param("root"), concrete_path("x")],
        };
        let literal = ResourceExpr::Literal {
            value: "/var/cache".into(),
        };
        let bindings = bind_positional(&["root".into()], std::slice::from_ref(&literal));
        assert_eq!(
            substitute_resource_expr(&expr, &bindings),
            ResourceExpr::Join {
                parts: vec![literal, concrete_path("x")],
            }
        );
    }

    #[test]
    fn free_parameter_stays_symbolic() {
        let expr = param("unbound");
        let out = substitute_resource_expr(&expr, &HashMap::new());
        assert_eq!(out, param("unbound"));
    }
}
